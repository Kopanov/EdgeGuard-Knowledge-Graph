"""A refreshed MISP attribute on a real Neo4j (2026-10): what the sync does with it.

``MISPWriter`` edits the stored copy of an indicator a source reports again
(``tests/test_misp_reobserved_indicator_refresh.py``): MISP stamps it anew and the source's dates
stay. The edited attribute is parsed as the sync parses it and merged with
``merge_indicators_batch`` onto a node that decay retired: the node's ``last_updated`` moves, the
decay retirement is lifted, and ``first_imported_at`` and both claims of the source stay where they
were. The writer also adds several-actor marks to the stored copy of an OTX indicator
(``tests/test_attribution_single_actor_reports.py``): the edited copy merged in three runs leaves the node
with the union of the marks, a batch row without marks clears none, and the query build_relationships
step 2d and the acceptance check read returns them (2026-10).
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
CREATE (:Source:{LABEL} {{source_id: 'alienvault_otx'}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'domain', value: 'held.it.example', uuid: 'u-held', source: ['alienvault_otx'],
        zone: ['global'], confidence_score: 0.5, edgeguard_managed: true, active: true,
        pulse_malware_actor_pairs: ['Crutch::Turla::p6']}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'domain', value: 'other.it.example', uuid: 'u-other', source: ['alienvault_otx'],
        zone: ['global'], confidence_score: 0.5, edgeguard_managed: true, active: true}})
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
    """The stored Feodo Tracker attribute after the refresh, as MISP 2.5 lists it: a new timestamp,
    the source's ``first_seen`` / ``last_seen`` unchanged."""
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
        "last_seen": "2024-06-01T00:00:00.000000+00:00",
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
    assert row["last_at"].to_native() == datetime(2024, 6, 1, tzinfo=timezone.utc), (
        "the last-seen claim stays the source's, not the time of the refresh"
    )


def _otx_copy(value: str, uuid: str, comment: str) -> dict:
    """An OTX indicator's stored copy as MISP 2.5 lists it, with the given comment."""
    return {
        "id": "1300",
        "event_id": "42",
        "type": "domain",
        "category": "Network activity",
        "to_ids": True,
        "uuid": uuid,
        "timestamp": str(int(datetime.now(timezone.utc).timestamp()) - 60),
        "comment": comment,
        "first_seen": None,
        "last_seen": None,
        "value": value,
        "Tag": [{"name": "source:AlienVault-OTX"}, {"name": "tlp:green"}, {"name": "zone:Global"}],
    }


def test_several_actor_marks_accumulate_on_the_indicator_and_the_step_2d_query_reads_them(client, raw_driver):
    import canonical_threat_actors
    from collectors.misp_writer import MISPWriter, _otx_meta_with_marks
    from run_misp_to_neo4j import MISPToNeo4jSync

    writer = MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)
    otx = {"tag": "alienvault_otx", "source": ["alienvault_otx"], "zone": ["global"], "confidence_score": 0.5}
    event = {"id": 42, "info": "EdgeGuard-alienvault_otx-2026-10-01", "date": "2026-10-01", "Tag": []}
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())

    def parsed(value: str, uuid: str, comment: str) -> dict:
        item, _ = syncer.parse_attribute(_otx_copy(value, uuid, comment), event)
        return item

    def stored(value: str, **fields) -> str:
        return writer.create_attribute({**otx, "indicator_type": "domain", "value": value, **fields})["comment"]

    # Run 1: the copy written while p6 named Turla alone, then edited by the writer when p6 was edited to
    # name several actors (``_carry_marks``): the pair stays, the mark is added.
    first = stored("held.it.example", pulse_id="p6", pulse_malware_actor_pairs=["Crutch::Turla::p6"])
    edited = _otx_meta_with_marks(first, ["p6"])
    assert edited is not None
    held = parsed("held.it.example", "6f3c1d5e-0000-4000-8000-000000001300", edited)
    assert held["several_actor_pulses"] == ["p6"]
    assert client.merge_indicators_batch([held], source_id="alienvault_otx") == (1, 0)
    # Run 2: a later pulse naming several actors lists the IOC.
    later = parsed(
        "held.it.example",
        "6f3c1d5e-0000-4000-8000-000000001301",
        stored("held.it.example", pulse_id="p7", several_actor_pulses=["p7"]),
    )
    assert client.merge_indicators_batch([later], source_id="alienvault_otx") == (1, 0)
    # Run 3: one batch, the IOC in a pulse naming one actor (a row without marks) and another IOC marked.
    unmarked = parsed(
        "held.it.example", "6f3c1d5e-0000-4000-8000-000000001302", stored("held.it.example", pulse_id="p8")
    )
    assert "several_actor_pulses" not in unmarked
    other = parsed(
        "other.it.example",
        "6f3c1d5e-0000-4000-8000-000000001303",
        stored("other.it.example", pulse_id="p9", several_actor_pulses=["p9"]),
    )
    assert client.merge_indicators_batch([unmarked, other], source_id="alienvault_otx") == (2, 0)

    with raw_driver.session() as session:
        marks = {
            r["v"]: sorted(r["marks"] or [])
            for r in session.run(
                f"MATCH (i:Indicator:{LABEL}) WHERE i.indicator_type = 'domain' "
                "RETURN i.value AS v, i.several_actor_pulses AS marks"
            )
        }
        pairs = session.run(
            f"MATCH (i:Indicator:{LABEL} {{value: 'held.it.example'}}) RETURN i.pulse_malware_actor_pairs AS p"
        ).single()["p"]
        row = session.run(canonical_threat_actors.INDICATOR_MARKED_REPORTS_QUERY).single()
    assert marks == {"held.it.example": ["p6", "p7"], "other.it.example": ["p9"]}, "accumulated, never overwritten"
    assert pairs == ["Crutch::Turla::p6"], "the pair written while p6 named one actor stays; step 2d skips it"
    assert sorted(row["pulses"]) == ["p6", "p7", "p9"] and row["indicators"] == 2
