"""Campaign sector labels on a real Neo4j (2026-11-02): a campaign carries the labels of its zones.

The sync labels a node by its sector zones (``:Finance`` for ``finance``, ``apply_sector_labels``) at its end;
``build_campaign_nodes`` runs after it and recomputes each campaign's zones from its active indicators. So
a campaign had no label until the next sync: after the 730-day baseline of 1 Nov 2026, 0 of 533 campaigns
carried one although 433 had a sector zone, and ``MATCH (c:Campaign:Finance)`` found none. The builder now
sets the labels itself (Step 6, ``sector_labels.CAMPAIGN_SECTOR_LABELS_CYPHER``): it adds those of the zones,
removes from a campaign EdgeGuard created those its zones no longer give, and leaves a partner's campaign
its own. The acceptance check 10n (``SECTOR_LABELS_CHECK_QUERY``) passes on the result, and fails on the
order before the fix.

The indicators are written as production writes them (the helpers of ``test_campaign_seen_dates_neo4j``:
the collector's OTX item with its zones, the attribute ``MISPWriter`` builds from it, ``parse_attribute``,
``merge_indicators_batch``), then labelled by the sync's ``apply_sector_labels``. Same guards as
``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, writes only nodes
labelled ``EdgeGuardIT``, refuses any other node.
"""

from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)
from test_campaign_seen_dates_neo4j import (  # noqa: E402  (the production write path of the indicators)
    CAMPAIGN,
    FIXTURE,
    _indicates,
    _merge,
    _now,
    _otx_item,
    _stored,
)

import neo4j_client  # noqa: E402
from sector_labels import SECTOR_LABELS, SECTOR_LABELS_CHECK_QUERY, check_params, check_verdict  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

ZONES = {"it-label-finance.example": ["finance"], "it-label-health.example": ["healthcare", "global"]}
GLOBAL_VALUE = "it-label-global.example"


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver, monkeypatch):
    import enrichment_jobs

    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(FIXTURE)
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()


def _sync(client, raw_driver) -> None:
    """The sync: the OTX indicators with their zones, linked to the family, then the sync's labels."""
    now = _now()
    attrs = []
    for n, value in enumerate([*ZONES, GLOBAL_VALUE]):
        item = _otx_item(value, now - timedelta(days=30), now - timedelta(days=1))
        item["zone"] = ZONES.get(value, ["global"])
        attrs.append(_stored(item, n, now))
    _merge(client, raw_driver, "alienvault_otx", attrs)
    _indicates(raw_driver, *ZONES, GLOBAL_VALUE)
    assert client.apply_sector_labels() >= 2


def _build(client, raw_driver) -> dict:
    """``build_campaign_nodes``; the campaign it creates gets the suite's label, so the cleanup removes it."""
    import enrichment_jobs

    try:
        return enrichment_jobs.build_campaign_nodes(client)
    finally:
        with raw_driver.session() as session:
            session.run(f"MATCH (c:Campaign) WHERE NOT c:{LABEL} SET c:{LABEL}")


def _campaign(raw_driver, name: str = CAMPAIGN):
    with raw_driver.session() as session:
        rec = session.run(
            "MATCH (c:Campaign {name: $name}) RETURN c.zone AS zone, "
            "[l IN labels(c) WHERE l IN $sector_labels] AS labels",
            name=name,
            sector_labels=list(SECTOR_LABELS),
        ).single()
    return (list(rec["zone"] or []), sorted(rec["labels"])) if rec else None


def _check(raw_driver) -> dict:
    with raw_driver.session() as session:
        return dict(session.run(SECTOR_LABELS_CHECK_QUERY, check_params()).single())


def test_indicators_carry_the_zones_the_collector_gave(client, raw_driver):
    """The fixture's premise: the write path keeps the zones and the sync labels the indicators."""
    _sync(client, raw_driver)
    with raw_driver.session() as session:
        rows = {
            r["value"]: (sorted(r["zone"]), sorted(r["labels"]))
            for r in session.run(
                f"MATCH (i:Indicator:{LABEL}) RETURN i.value AS value, i.zone AS zone, "
                "[l IN labels(i) WHERE l IN $sector_labels] AS labels",
                sector_labels=list(SECTOR_LABELS),
            )
        }
    assert rows["it-label-finance.example"] == (["finance"], ["Finance"])
    assert rows["it-label-health.example"][1] == ["Healthcare"]
    assert rows[GLOBAL_VALUE] == (["global"], [])


def test_campaign_carries_the_labels_of_its_zones(client, raw_driver):
    _sync(client, raw_driver)
    results = _build(client, raw_driver)
    zone, labels = _campaign(raw_driver)
    assert {"finance", "healthcare"} <= set(zone)
    assert labels == ["Finance", "Healthcare"]
    assert (results["sector_labels_added"], results["sector_labels_removed"]) == (2, 0)
    row = _check(raw_driver)
    assert check_verdict(row) is True, row
    assert row["nodes"] >= 3

    again = _build(client, raw_driver)
    assert (again["sector_labels_added"], again["sector_labels_removed"]) == (0, 0), "a second run changes nothing"
    assert _campaign(raw_driver)[1] == ["Finance", "Healthcare"]


def test_label_leaves_with_the_zone(client, raw_driver):
    """A campaign's zones are those of its active indicators: when the finance indicator expires, the
    campaign loses ``finance`` and ``:Finance``; the next sync does not bring the label back."""
    _sync(client, raw_driver)
    _build(client, raw_driver)
    with raw_driver.session() as session:
        session.run(f"MATCH (i:Indicator:{LABEL} {{value: 'it-label-finance.example'}}) SET i.active = false")
    results = _build(client, raw_driver)
    zone, labels = _campaign(raw_driver)
    assert "finance" not in zone
    assert labels == ["Healthcare"]
    assert (results["sector_labels_added"], results["sector_labels_removed"]) == (0, 1)
    client.apply_sector_labels()
    assert _campaign(raw_driver)[1] == ["Healthcare"]
    assert check_verdict(_check(raw_driver)) is True


def test_partner_campaign_gains_labels_and_keeps_its_own(client, raw_driver):
    _sync(client, raw_driver)
    with raw_driver.session() as session:
        session.run(f"CREATE (:Campaign:{LABEL}:Finance {{name: 'it-partner Campaign', zone: ['energy']}})")
    _build(client, raw_driver)
    assert _campaign(raw_driver, "it-partner Campaign")[1] == ["Energy", "Finance"]


def test_check_fails_on_the_order_before_the_fix(client, raw_driver, monkeypatch):
    """Without Step 6 the campaign has no label after a baseline (the sync labelled before it existed):
    the check fails until a later sync labels it. A sector label the zones do not give fails it too."""
    import enrichment_jobs

    monkeypatch.setattr(
        enrichment_jobs, "CAMPAIGN_SECTOR_LABELS_CYPHER", "RETURN 0 AS campaigns, 0 AS added, 0 AS removed"
    )
    _sync(client, raw_driver)
    _build(client, raw_driver)
    assert _campaign(raw_driver)[1] == []
    row = _check(raw_driver)
    assert check_verdict(row) is False
    assert (row["missing_label"], row["stray_label"]) == (1, 0)
    assert row["examples"] == [{"label": "Campaign", "missing": ["Finance", "Healthcare"], "stray": []}]

    client.apply_sector_labels()  # the next sync
    assert check_verdict(_check(raw_driver)) is True

    with raw_driver.session() as session:
        session.run("MATCH (c:Campaign {name: $name}) SET c:Energy", name=CAMPAIGN)
    row = _check(raw_driver)
    assert check_verdict(row) is False and (row["missing_label"], row["stray_label"]) == (0, 1)


def test_check_is_informational_without_zoned_nodes(client, raw_driver):
    assert check_verdict(_check(raw_driver)) is None
