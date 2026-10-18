"""One aging rule for indicators, whoever supplied them (2026-10-16, ``src/indicator_aging.py``).

The owner's rule: aging depends on the kind of fact, not on who supplied it or who created the
node. Every Indicator ages from the latest report of any source (the source's own last-report
date, capped at the MISP record time; the MISP record time when the source gives none; when
EdgeGuard created the node when no report dated it), with the confidence a source gave times the
factor of the tier reached, and is retired after 730 days without a report. Nothing else ages.

These unit tests run the real callers on fixtures shaped like the MISP 2.5 attributes the sync
reads (``timestamp`` epoch strings or PyMISP datetimes, the native ``last_seen``, ``uuid``, the
source tag) and check what reaches the writer, the job's statements, the time of an evaluation,
the readers and the configuration. The Cypher semantics run on Neo4j in
``tests/test_indicator_aging_neo4j.py``.
"""

from __future__ import annotations

import logging
import random
import sys
from datetime import datetime, timedelta, timezone
from itertools import pairwise
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import enrichment_jobs  # noqa: E402
import indicator_aging as ia  # noqa: E402
import run_misp_to_neo4j  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync, _dedupe_parsed_items, misp_report_times  # noqa: E402

UTC = timezone.utc
T_RECORDED = datetime(2026, 10, 14, 6, 31, 5, tzinfo=UTC)  # the 730-day baseline push
EVENT = {"id": "157", "info": "EdgeGuard-feodo_tracker-2026-10-14", "date": "2026-10-14", "Tag": []}


def _attr(
    value: str,
    uuid: str,
    *,
    timestamp=T_RECORDED,
    last_seen=None,
    tag: str = "Feodo-Tracker",
    attr_type: str = "ip-dst",
    first_seen: str | None = "2024-05-01T10:00:00.000000+00:00",
    comment: str = 'TF_META:{"malware_family": "Emotet", "last_seen": "2024-06-01"}',
    confidence: str | None = None,
) -> dict:
    """One attribute as MISP 2.5 ``events/view`` lists it (PyMISP ``to_dict`` gives datetimes)."""
    if isinstance(timestamp, datetime) and timestamp.tzinfo is not None:
        ts = str(int(timestamp.timestamp()))
    else:
        ts = timestamp  # a PyMISP naive datetime, an epoch string, None, ...
    tags = [{"name": f"source:{tag}"}, {"name": "tlp:white"}, {"name": "zone:Global"}]
    if confidence:
        tags.append({"name": f"confidence:{confidence}"})
    return {
        "id": str(abs(hash(uuid)) % 100000),
        "event_id": "157",
        "category": "Network activity",
        "type": attr_type,
        "to_ids": False,
        "uuid": uuid,
        "timestamp": ts,
        "comment": comment,
        "first_seen": first_seen,
        "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else last_seen,
        "value": value,
        "Tag": tags,
    }


def _parse(attr: dict, event: dict = EVENT) -> dict:
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attr, event)
    assert item is not None
    return item


# ================================================================ configuration


class TestPolicy:
    def test_defaults(self):
        p = ia.load_aging_policy({})
        assert (p.tier_days, p.factors, p.retire_days) == ((90, 180, 365), (0.85, 0.70, 0.55), 730)

    def test_env_overrides(self):
        p = ia.load_aging_policy({ia.TIER_DAYS_ENV: " 30, 60 ", ia.FACTORS_ENV: "0.9,0.5", ia.RETIRE_DAYS_ENV: "365"})
        assert (p.tier_days, p.factors, p.retire_days) == ((30, 60), (0.9, 0.5), 365)

    @pytest.mark.parametrize(
        "env, message",
        [
            ({ia.TIER_DAYS_ENV: "180,90,365"}, "strictly ascending"),
            ({ia.TIER_DAYS_ENV: "90,90,365"}, "strictly ascending"),
            ({ia.TIER_DAYS_ENV: "0,180,365"}, "positive"),
            ({ia.TIER_DAYS_ENV: "90,x"}, "comma-separated"),
            ({ia.FACTORS_ENV: "0.85,0.70"}, "one factor per tier day"),
            ({ia.FACTORS_ENV: "0.85,0.70,0"}, "(0, 1]"),
            ({ia.FACTORS_ENV: "0.85,1.2,0.55"}, "(0, 1]"),
            ({ia.RETIRE_DAYS_ENV: "365"}, "above the last tier day"),
            ({ia.RETIRE_DAYS_ENV: "two years"}, "whole number"),
        ],
    )
    def test_invalid_settings_are_refused(self, env, message):
        with pytest.raises(ValueError, match=message.replace("(", r"\(").replace(")", r"\)").replace("[", r"\[")):
            ia.load_aging_policy(env)

    def test_an_invalid_setting_stops_the_indicator_write(self, monkeypatch):
        """A wrong setting fails loudly instead of aging the graph by an unintended rule."""
        monkeypatch.setenv(ia.RETIRE_DAYS_ENV, "100")
        with pytest.raises(ValueError):
            ia.aging_map("n", "datetime()")

    def test_tiers_factors_and_floor(self):
        p = ia.AgingPolicy()
        assert [p.tier(d) for d in (None, -3, 0, 89, 90, 179, 180, 364, 365, 729, 730, 5000)] == [
            0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 3, 3,
        ]  # fmt: skip
        assert [p.factor(t) for t in range(4)] == [1.0, 0.85, 0.70, 0.55]
        assert [p.tier_start(t) for t in range(4)] == [0, 90, 180, 365]
        assert p.confidence(0.5, 90) == 0.43, "round half up, as Cypher round(x, 2)"
        assert p.confidence(0.12, 400) == 0.10

    def test_the_rendered_rule_follows_the_policy(self, monkeypatch):
        monkeypatch.setenv(ia.TIER_DAYS_ENV, "30,60")
        monkeypatch.setenv(ia.FACTORS_ENV, "0.9,0.5")
        monkeypatch.setenv(ia.RETIRE_DAYS_ENV, "400")
        body = ia.aging_map("n", "datetime()")
        assert "[_t IN [30, 60] WHERE _t <= _age]" in body
        assert "[1.0, 0.9, 0.5][_tier]" in body and "[0, 30, 60][_tier]" in body
        assert "_age >= 400" in body and "duration({days: 400})" in body

    @pytest.mark.parametrize(
        "reported, imported, env, basis",
        [
            (datetime(2026, 9, 1, tzinfo=UTC), datetime(2026, 1, 1, tzinfo=UTC), {}, datetime(2026, 9, 1, tzinfo=UTC)),
            (None, datetime(2026, 1, 1, 12, 30, tzinfo=UTC), {}, datetime(2026, 1, 1, 12, 30, tzinfo=UTC)),
            (datetime(2024, 2, 29, tzinfo=UTC), None, {ia.RETIRE_DAYS_ENV: "400"}, datetime(2024, 2, 29, tzinfo=UTC)),
            (
                datetime(2026, 9, 1, 23, 59, 59, 999999, tzinfo=UTC),
                datetime(2026, 1, 1, tzinfo=UTC),
                {ia.TIER_DAYS_ENV: "30,60", ia.FACTORS_ENV: "0.9,0.5", ia.RETIRE_DAYS_ENV: "90"},
                datetime(2026, 9, 1, 23, 59, 59, 999999, tzinfo=UTC),
            ),
        ],
    )
    def test_the_retirement_time_is_when_the_rule_retires(self, reported, imported, env, basis):
        """``retirement_time`` (the STIX ``valid_until`` of an indicator not yet retired) is the time at which
        the rule retires the node: the basis ``coalesce(last_reported_at, first_imported_at)`` plus the retire
        days, the ``retired_at`` the rule then writes. At that time the age in whole days
        (``duration.inDays(_basis, _at).days``) reaches the retire days; one second earlier it does not."""
        policy = ia.load_aging_policy(env)
        when = ia.retirement_time(reported, imported, policy)
        assert when == basis + timedelta(days=policy.retire_days)
        assert (when - basis).days == policy.retire_days
        assert (when - timedelta(seconds=1) - basis).days == policy.retire_days - 1
        body = ia.aging_map("n", "datetime()", policy)
        assert ia.basis_expr("n") == "coalesce(n.last_reported_at, n.first_imported_at)"
        assert f"[_basis IN [{ia.basis_expr('n')}]" in body
        assert f"_age >= {policy.retire_days}" in body
        assert f"retired_at: CASE WHEN _age IS NULL OR {ia.manual_decommission_expr('n')} THEN n.retired_at " in body
        assert f"WHEN _age >= {policy.retire_days} THEN _basis + duration({{days: {policy.retire_days}}})" in body

    def test_no_time_gives_no_retirement_time(self):
        assert ia.retirement_time(None, None, ia.AgingPolicy()) is None

    def test_the_retirement_time_reads_the_configured_policy(self, monkeypatch):
        monkeypatch.setenv(ia.RETIRE_DAYS_ENV, "500")
        basis = datetime(2026, 1, 1, tzinfo=UTC)
        assert ia.retirement_time(basis, None) == basis + timedelta(days=500)
        monkeypatch.setenv(ia.RETIRE_DAYS_ENV, "100")
        with pytest.raises(ValueError):
            ia.retirement_time(basis, None)


class TestOneDefinitionWithoutOwnership:
    def test_no_aging_statement_reads_the_ownership_markers(self):
        policy = ia.AgingPolicy()
        texts = [
            ia.aging_map("n", "datetime()", policy),
            ia.node_report_items("n", "item.report", "item.source_id"),
            ia.edge_report_items("r", "item.report", "item.source_id"),
            ia.source_confidence_item("n", "item.confidence"),
            *enrichment_jobs._aging_job_statements(policy),
            enrichment_jobs._AGING_STATS_CYPHER,
        ]
        for text in texts:
            assert "edgeguard_managed" not in text and "edgeguard_enriched" not in text
            assert "last_updated" not in text, "the last database write is not an aging time"
            assert '"' not in text, "single quotes only (the fragments run inside apoc strings)"

    def test_the_rule_sets_exactly_the_aging_fields(self):
        """2026-10-16: the keys of ``aging_map`` are ``AGING_FIELDS`` and ``aging_evaluated_at``, and the
        job writes a node when any of the ``AGING_FIELDS`` differs from the stored value
        (``aging_basis`` among them, so a stale one is corrected); a later evaluation time alone is no
        change, and a node without a stored time is written once to store it."""
        import re

        body = ia.aging_map("n", "datetime()")
        keys = tuple(re.findall(r"(?:\{|, )([a-z_]+): CASE WHEN", body))
        assert keys == (
            "aging_basis",
            "aging_tier",
            "aging_factor",
            "aging_since",
            "confidence_score",
            "active",
            "retired_at",
            "retired_by",
            "aging_evaluated_at",
        )
        assert keys == ia.AGING_MAP_KEYS == ia.AGING_FIELDS + (ia.EVALUATED_AT,)
        predicate = ia.changed_predicate("n", "aged")
        assert predicate.startswith(
            "((n.aging_evaluated_at IS NULL AND aged.aging_evaluated_at IS NOT NULL) "
            "OR any(_k IN ['aging_basis', 'aging_tier', 'aging_factor', 'aging_since', "
        )
        listed = predicate.split("any(_k IN [", 1)[1].split("]", 1)[0]
        assert listed == ", ".join(f"'{field}'" for field in ia.AGING_FIELDS)
        assert "'aging_evaluated_at'" not in listed, "a later time alone does not write a node"
        _outer, inner, count = enrichment_jobs._aging_job_statements(ia.AgingPolicy())
        assert f"WHERE {predicate} SET n += aged" in inner and f"WHERE {predicate} RETURN count(n)" in count

    def test_aging_basis_is_derived_from_the_recorded_report(self):
        """2026-10-16: the report items record the kind of the latest report (``last_reported_basis``);
        the rule derives ``aging_basis`` from it (``first_imported`` without a report), so the job puts
        right an ``aging_basis`` that disagrees with the stored report."""
        report = ia.node_report_items("n", "item.report", "item.source_id")
        assert "last_reported_basis: item.report.reported_basis" in report
        assert "aging_basis" not in report, "the report records the kind; the rule sets aging_basis"
        body = ia.aging_map("n", "datetime()")
        assert (
            "aging_basis: CASE WHEN _age IS NULL THEN n.aging_basis WHEN n.last_reported_at IS NULL "
            "THEN 'first_imported' ELSE coalesce(n.last_reported_basis, n.aging_basis) END"
        ) in body
        assert "last_reported_basis" not in ia.edge_report_items("r", "item.report", "item.source_id")

    def test_the_job_selects_the_changing_indicators_and_locks_each_before_it_reads_it(self):
        """2026-10-16: ``outer`` selects, without a lock, the Indicators with a time whose aging changes;
        ``inner`` takes each node's write lock before it reads anything of the node, then evaluates the
        rule again and writes only where a value still changes, so a write that committed while the job
        waited is what the rule reads (``tests/test_indicator_aging_neo4j.py`` runs the race)."""
        policy = ia.AgingPolicy()
        outer, inner, count = enrichment_jobs._aging_job_statements(policy)
        changed = (
            f"WITH n, {ia.aging_map('n', enrichment_jobs.AGING_JOB_TIME, policy)} AS aged "
            f"WHERE {ia.changed_predicate('n', 'aged')}"
        )
        select = f"MATCH (n:Indicator) WHERE coalesce(n.last_reported_at, n.first_imported_at) IS NOT NULL {changed}"
        assert outer == f"{select} RETURN n"
        assert count == f"{select} RETURN count(n) AS changed"
        assert inner == f"CALL apoc.lock.nodes([n]) {changed} SET n += aged"
        assert inner.index("CALL apoc.lock.nodes([n])") == 0 and "n." not in inner.split(" WITH ", 1)[0], (
            "no property of the node is read before the lock"
        )


# ================================================================ the report of one MISP attribute


class TestMispReportTimes:
    def test_feodo_last_online_dates_the_report(self):
        """Feodo Tracker stores ``last_online`` as ``last_seen``: older than the MISP record time,
        so the indicator ages from the source's date (the baseline's push time does not make it new)."""
        item = _parse(_attr("203.0.113.10", "a-1", last_seen="2024-06-01T00:00:00.000000+00:00"))
        assert item["recorded_at"] == T_RECORDED.isoformat()
        assert item["reported_at"] == "2024-06-01T00:00:00+00:00"
        assert item["reported_basis"] == "source_date" and item["report_ref"] == "a-1"

    def test_without_a_source_date_the_misp_time_dates_the_report(self):
        """SSL Blacklist and MalwareBazaar store no ``last_seen``; ThreatFox may send none."""
        sslbl = _attr(
            "d6a5a1b2c3d4e5f60718293a4b5c6d7e8f901234",
            "a-2",
            tag="SSL-Blacklist",
            attr_type="x509-fingerprint-sha1",
            comment="SSL Blacklist: Dridex C&C",
        )
        item = _parse(sslbl)
        assert item["reported_at"] == item["recorded_at"] == T_RECORDED.isoformat()
        assert item["reported_basis"] == "misp_recorded"

    def test_a_source_date_later_than_the_misp_time_is_capped(self):
        later = T_RECORDED + timedelta(days=3)
        item = _parse(_attr("203.0.113.11", "a-3", tag="ThreatFox", last_seen=later))
        assert item["reported_at"] == T_RECORDED.isoformat() and item["reported_basis"] == "misp_recorded"

    def test_otx_pulse_modified(self):
        otx = _attr(
            "evil.it.example",
            "a-4",
            tag="AlienVault-OTX",
            attr_type="domain",
            first_seen="2026-09-01T08:00:00.000000+00:00",
            last_seen="2026-09-20T12:30:00.000000+00:00",
            comment='OTX_META:{"pulse_id": "p1", "pulse_name": "x"}',
        )
        item = _parse(otx)
        assert item["reported_at"] == "2026-09-20T12:30:00+00:00" and item["reported_basis"] == "source_date"

    def test_pymisp_datetimes_convert_as_the_incremental_filter_does(self):
        naive = T_RECORDED.replace(tzinfo=None)  # PyMISP to_dict(): naive UTC
        item = _parse(_attr("203.0.113.12", "a-5", timestamp=naive, last_seen=None))
        assert item["recorded_at"] == T_RECORDED.isoformat()
        aware = T_RECORDED.astimezone(timezone(timedelta(hours=2)))
        assert misp_report_times({"timestamp": aware, "uuid": "x"})["recorded_at"] == T_RECORDED.isoformat()
        assert run_misp_to_neo4j._attribute_changed_since({"timestamp": naive}, T_RECORDED)
        assert not run_misp_to_neo4j._attribute_changed_since({"timestamp": naive}, T_RECORDED + timedelta(seconds=1))

    @pytest.mark.parametrize("timestamp", [None, "", "not-a-time"])
    def test_without_a_usable_timestamp_the_attribute_dates_nothing(self, timestamp):
        times = misp_report_times({"timestamp": timestamp, "uuid": "a-6", "last_seen": "2024-06-01"})
        assert times == {"recorded_at": None, "reported_at": None, "report_ref": "a-6", "reported_basis": None}
        assert run_misp_to_neo4j._attribute_changed_since({"timestamp": timestamp}, T_RECORDED), "counts as changed"

    def test_a_sentinel_source_date_cannot_retire_an_indicator(self):
        item = _parse(_attr("203.0.113.13", "a-7", last_seen="0001-01-01T00:00:00+00:00"))
        assert item["reported_basis"] == "misp_recorded"

    def test_an_untrusted_creator_dates_nothing_with_its_claim(self, monkeypatch):
        """With the trust check configured, a source date from an event of another organisation is
        refused like the source's other dates; the MISP time still dates the report."""
        monkeypatch.setattr(run_misp_to_neo4j, "is_attribute_creator_trusted", lambda event: (False, "not_allowlisted"))
        item = _parse(_attr("203.0.113.14", "a-8", last_seen="2024-06-01T00:00:00+00:00"))
        assert item["reported_basis"] == "misp_recorded"

    def test_a_comment_only_edit_does_not_refresh_a_dated_item(self):
        """An edit of a stored OTX copy's comment only (by an analyst in MISP, for example; EdgeGuard
        makes none since 2026-10): MISP stamps it anew (T moves), ``last_seen`` stays, so the report time
        stays the pulse's date."""
        before = _attr(
            "held.it.example",
            "a-9",
            tag="AlienVault-OTX",
            attr_type="domain",
            last_seen="2026-07-01T00:00:00.000000+00:00",
            comment='OTX_META:{"pulse_id": "p6"}',
        )
        after = dict(before, timestamp=str(int((T_RECORDED + timedelta(days=40)).timestamp())))
        after["comment"] = 'OTX_META:{"pulse_id": "p6", "pulse_name": "Crutch campaign (reviewed)"}'
        assert _parse(before)["reported_at"] == _parse(after)["reported_at"] == "2026-07-01T00:00:00+00:00"

    def test_only_indicator_items_carry_a_report(self):
        cve = _attr("CVE-2024-3400", "a-10", tag="NVD", attr_type="vulnerability", comment="")
        item = _parse(cve)
        assert not any(key in item for key in ia.REPORT_KEYS), "a CVE does not age"


# ================================================================ duplicates and the two sync paths


def _report_of(item: dict) -> tuple:
    return tuple(
        item.get(k) for k in ("reported_at", "report_ref", "reported_basis", "recorded_at", "confidence_score")
    )


class TestDuplicates:
    def _pair(self):
        older = _attr("203.0.113.20", "b-2", last_seen="2026-01-01T00:00:00+00:00", confidence="low")
        newer = _attr(
            "203.0.113.20",
            "b-9",
            timestamp=T_RECORDED - timedelta(days=5),
            last_seen="2026-08-01T00:00:00+00:00",
            confidence="high",
        )
        return _parse(older), _parse(newer)

    def test_either_order_keeps_the_latest_report_and_the_highest_confidence(self):
        older, newer = self._pair()
        a = _dedupe_parsed_items([dict(older), dict(newer)])
        b = _dedupe_parsed_items([dict(newer), dict(older)])
        assert len(a) == len(b) == 1
        assert (
            _report_of(a[0])
            == _report_of(b[0])
            == (
                "2026-08-01T00:00:00+00:00",
                "b-9",
                "source_date",
                T_RECORDED.isoformat(),  # the later MISP record time, from the other duplicate
                0.8,
            )
        )

    def test_an_equal_time_goes_to_the_smaller_reference(self):
        x = _parse(_attr("203.0.113.21", "c-2", last_seen="2026-08-01T00:00:00+00:00"))
        y = _parse(_attr("203.0.113.21", "c-1", last_seen="2026-08-01T00:00:00+00:00"))
        assert _dedupe_parsed_items([dict(x), dict(y)])[0]["report_ref"] == "c-1"
        assert _dedupe_parsed_items([dict(y), dict(x)])[0]["report_ref"] == "c-1"

    def test_a_duplicate_of_another_source_is_not_folded(self):
        feodo = _parse(_attr("203.0.113.22", "d-1", last_seen="2024-06-01T00:00:00+00:00"))
        threatfox = _parse(_attr("203.0.113.22", "d-2", tag="ThreatFox", last_seen="2026-08-01T00:00:00+00:00"))
        kept = _dedupe_parsed_items([dict(feodo), dict(threatfox)])
        assert kept[0]["tag"] == "feodo_tracker" and kept[0]["report_ref"] == "d-1"


def _fold(items: list) -> dict:
    """What the forward-only node write keeps from a sequence of items (the Python form of
    ``indicator_aging.node_report_items`` and ``source_confidence_item``)."""
    nodes: dict = {}
    for it in items:
        key = (it["indicator_type"], it["value"])
        node = nodes.setdefault(key, {"reported": None, "recorded": None, "conf": None})
        rep = (datetime.fromisoformat(it["reported_at"]), it["report_ref"], it["tag"])
        cur = node["reported"]
        if cur is None or rep[0] > cur[0] or (rep[0] == cur[0] and rep[1:] < cur[1:]):
            node["reported"] = rep + (it["reported_basis"],)
        rec = datetime.fromisoformat(it["recorded_at"])
        node["recorded"] = rec if node["recorded"] is None or rec > node["recorded"] else node["recorded"]
        node["conf"] = it["confidence_score"] if node["conf"] is None else max(node["conf"], it["confidence_score"])
    return nodes


def _event_attributes() -> list:
    """An event with three indicators, two of them listed twice (two pulses / two feed rows)."""
    return [
        _attr("203.0.113.30", "e-1", last_seen="2026-02-01T00:00:00+00:00", confidence="low"),
        _attr("203.0.113.31", "e-2", last_seen=None),
        _attr("203.0.113.30", "e-3", timestamp=T_RECORDED - timedelta(hours=3), last_seen="2026-09-01T00:00:00+00:00"),
        _attr("203.0.113.32", "e-4", last_seen="2025-01-01T00:00:00+00:00", confidence="high"),
        _attr("203.0.113.32", "e-0", last_seen="2025-01-01T00:00:00+00:00"),
    ]


def _written(path: str, attributes: list, monkeypatch) -> list:
    """The indicator items the sync hands to ``merge_indicators_batch`` on ``path``."""
    monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 1)
    neo4j = MagicMock()
    rows: list = []
    neo4j.merge_indicators_batch.side_effect = lambda items, source_id: (rows.extend(items), (len(items), 0))[1]
    sync = MISPToNeo4jSync(neo4j_client=neo4j)
    sync._create_relationships = lambda rels, source_id: 0
    sync._write_cross_item_relationships = lambda rels: 0
    getattr(sync, path)("157", EVENT, attributes)
    return rows


class TestBothSyncPathsAndAnyOrder:
    def test_the_in_memory_and_paged_paths_in_any_order_give_the_same_reports(self, monkeypatch):
        attrs = _event_attributes()
        expected = _fold(_written("_process_event_attributes", attrs, monkeypatch))
        rng = random.Random(16)
        for path in ("_process_event_attributes", "_process_large_event_paged"):
            for _ in range(4):
                shuffled = list(attrs)
                rng.shuffle(shuffled)
                assert _fold(_written(path, shuffled, monkeypatch)) == expected, path
        assert expected[("ipv4", "203.0.113.30")]["reported"][:2] == (
            datetime(2026, 9, 1, tzinfo=UTC),
            "e-3",
        )
        assert expected[("ipv4", "203.0.113.32")]["reported"][1] == "e-0", "an equal time: the smaller uuid"

    def test_every_written_indicator_carries_its_report(self, monkeypatch):
        for row in _written("_process_large_event_paged", _event_attributes(), monkeypatch):
            assert row["recorded_at"] and row["reported_at"] and row["report_ref"] and row["reported_basis"]


# ================================================================ the writers


def _capturing_client():
    import neo4j_client as nc

    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.driver = MagicMock()
    client._connection_healthy = True
    session = MagicMock()
    session.run.return_value.single.return_value = None
    client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return client, session


class TestWriters:
    def test_the_batch_sends_each_item_report(self, monkeypatch):
        import neo4j_client as nc

        sent: list = []
        monkeypatch.setattr(
            nc, "_execute_batch_with_retry", lambda driver, query, **kw: (sent.append(kw), (True, kw["batch_len"]))[1]
        )
        client, _ = _capturing_client()
        item = _parse(_attr("203.0.113.40", "f-1", last_seen="2026-08-01T00:00:00+00:00"))
        client.merge_indicators_batch([item], source_id="feodo_tracker")
        (row,) = sent[0]["query_kwargs"]["batch"]
        assert row["report"] == {
            "recorded_at": T_RECORDED.isoformat(),
            "reported_at": "2026-08-01T00:00:00+00:00",
            "report_ref": "f-1",
            "reported_basis": "source_date",
        }

    def test_the_batch_statement_carries_no_time(self):
        """2026-10-16: the sync passes no aging time: ``MISPToNeo4jSync`` takes none, and
        ``merge_indicators_batch`` sends ``session.run`` the batch and the source uuid only; the rule
        in the statement reads the database's current time. A real client built without a connection;
        a strict driver records each statement (any other driver call fails the test)."""
        import inspect

        import neo4j_client as nc

        runs: list = []
        counters = SimpleNamespace(nodes_created=1, properties_set=1, relationships_created=1)

        class _Result:
            def consume(self):
                return SimpleNamespace(counters=counters)

        class _Session:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def run(self, query, **params):
                runs.append((query, params))
                return _Result()

        class _Driver:
            def session(self, **kwargs):
                return _Session()

        assert list(inspect.signature(MISPToNeo4jSync.__init__).parameters) == [
            "self",
            "misp_url",
            "misp_api_key",
            "neo4j_client",
        ]
        client = nc.Neo4jClient("bolt://edgeguard-test.invalid:7687", "neo4j", "unused")
        assert client.driver is None
        assert MISPToNeo4jSync(neo4j_client=client).neo4j is client
        client.driver = _Driver()
        item = _parse(_attr("203.0.113.42", "f-2", last_seen="2026-08-01T00:00:00+00:00"))
        assert client.merge_indicators_batch([item], source_id="feodo_tracker") == (1, 0)
        ((query, params),) = [r for r in runs if "UNWIND $batch as item" in r[0]]
        assert set(params) == {"batch", "source_node_uuid", "timeout"}, "the statement's parameters and its limit"
        assert ia.aging_set_clause("n") in query

    @pytest.mark.parametrize("source_id", ["stix_import", "virustotal"])
    def test_command_line_writers_record_no_report(self, source_id):
        """The STIX import and the VirusTotal re-enrichment go through ``merge_indicator``: the same
        rule, no report time (a new node ages from first_imported_at)."""
        client, session = _capturing_client()
        client.merge_indicator(
            {"indicator_type": "ipv4", "value": "203.0.113.41", "zone": ["global"], "tag": source_id},
            source_id=source_id,
        )
        merge = next(c for c in session.run.call_args_list if c.args and "MERGE (n:Indicator" in c.args[0])
        assert merge.kwargs["report"] == dict.fromkeys(ia.REPORT_KEYS)
        assert ia.aging_set_clause("n") in merge.args[0]


# ================================================================ the job


class _JobSession:
    def __init__(self, stats_rows, changed=3, iterate=None):
        self.calls: list = []
        self.stats_rows = stats_rows
        self.changed = changed
        self.iterate = iterate or {"batches": 1, "total": 10}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        if query.startswith("MATCH (n:Indicator) WHERE coalesce"):
            result.single.return_value = {"changed": self.changed}
        elif query.startswith("CALL apoc.periodic.iterate"):
            result.single.return_value = self.iterate
        else:
            result.__iter__ = lambda _self: iter(self.stats_rows)
        return result


def _job_client(session):
    return SimpleNamespace(driver=SimpleNamespace(session=lambda **kw: session))


STATS = [
    {"tier": 0, "basis": "source_date", "retired": False, "no_time": False, "c": 5},
    {"tier": 1, "basis": "misp_recorded", "retired": False, "no_time": False, "c": 2},
    {"tier": 3, "basis": "source_date", "retired": True, "no_time": False, "c": 4},
    {"tier": 0, "basis": "first_imported", "retired": False, "no_time": False, "c": 1},
    {"tier": None, "basis": None, "retired": False, "no_time": True, "c": 0},
]


class TestTheJob:
    def test_it_runs_at_the_database_time_and_reports_the_state(self, caplog):
        """2026-10-16: production passes no time: ``$as_of`` is null and the statements evaluate the rule
        at ``coalesce(datetime($as_of), datetime())``, the database's current time (each batch of
        ``apoc.periodic.iterate`` reads it when its transaction starts)."""
        session = _JobSession(STATS)
        with caplog.at_level(logging.INFO, logger="enrichment_jobs"):
            result = enrichment_jobs.decay_ioc_confidence(_job_client(session))
        count, iterate, stats = session.calls
        assert count[1]["as_of"] is None and iterate[1]["as_of"] is None
        assert enrichment_jobs.AGING_JOB_TIME == "coalesce(datetime($as_of), datetime())"
        outer, inner, count_query = enrichment_jobs._aging_job_statements(ia.load_aging_policy())
        assert count[0] == count_query
        assert (iterate[1]["outer"], iterate[1]["inner"]) == (outer, inner)
        assert enrichment_jobs.AGING_JOB_TIME in inner and enrichment_jobs.AGING_JOB_TIME in outer
        assert "params: {as_of: $as_of}" in iterate[0]
        assert result["as_of"] is None and result["changed"] == 3
        assert result["tiers"] == {"tier_0": 6, "tier_1": 2, "tier_2": 0, "tier_3": 4}
        assert result["retired"] == 4 and result["no_time"] == 0
        assert result["by_basis"] == {"source_date": 9, "misp_recorded": 2, "first_imported": 1}
        assert "at the database's current time: 3 Indicator(s) changed" in caplog.text
        assert "retired (from 730 d): 4" in caplog.text
        assert "first_imported=1" in caplog.text and "with no time at all: 0" in caplog.text

    def test_a_test_may_give_the_job_a_time(self, caplog):
        """``as_of`` is for tests only; it reaches the statements as ``$as_of`` (ISO-8601 UTC) and is
        lifted per node like the database's time (``TestTheTimeNeverMovesBackwards``)."""
        session = _JobSession(STATS)
        as_of = datetime(2026, 10, 16, 5, 0, tzinfo=timezone(timedelta(hours=2)))
        with caplog.at_level(logging.INFO, logger="enrichment_jobs"):
            result = enrichment_jobs.decay_ioc_confidence(_job_client(session), as_of=as_of)
        count, iterate, _stats = session.calls
        assert count[1]["as_of"] == iterate[1]["as_of"] == result["as_of"] == "2026-10-16T03:00:00+00:00"
        assert "[AGING] at 2026-10-16T03:00:00+00:00: 3 Indicator(s) changed" in caplog.text

    def test_indicators_without_a_time_are_counted_and_warned(self, caplog):
        session = _JobSession(STATS[:1] + [{"tier": None, "basis": None, "retired": False, "no_time": True, "c": 2}])
        with caplog.at_level(logging.WARNING, logger="enrichment_jobs"):
            result = enrichment_jobs.decay_ioc_confidence(_job_client(session), as_of="2026-10-16T00:00:00Z")
        assert result["no_time"] == 2 and "neither last_reported_at nor first_imported_at" in caplog.text

    def test_a_failed_batch_fails_the_job(self):
        session = _JobSession(STATS, iterate={"failedBatches": 1, "errorMessages": {"oom": 1}})
        with pytest.raises(RuntimeError, match="AGING"):
            enrichment_jobs.decay_ioc_confidence(_job_client(session), as_of=None)

    def test_the_forms_of_a_test_time(self):
        assert ia.evaluation_time("2026-10-16T03:00:00Z") == datetime(2026, 10, 16, 3, tzinfo=UTC)
        assert ia.evaluation_time(datetime(2026, 10, 16, 3)) == datetime(2026, 10, 16, 3, tzinfo=UTC)
        cest = datetime(2026, 10, 16, 5, tzinfo=timezone(timedelta(hours=2)))
        assert ia.evaluation_time(cest) == datetime(2026, 10, 16, 3, tzinfo=UTC)
        assert type(ia.evaluation_time(cest)) is datetime
        with pytest.raises(TypeError):
            ia.evaluation_time(None)

    def test_the_runner_passes_no_time_and_ages_before_the_campaigns(self, monkeypatch):
        seen: list = []
        for name in (
            "bridge_vulnerability_cve",
            "merge_alias_duplicate_actors",
            "merge_malware_attack_twins",
            "build_campaign_nodes",
            "calibrate_cooccurrence_confidence",
            "enrich_cve_epss",
        ):
            monkeypatch.setattr(enrichment_jobs, name, lambda c, _n=name: seen.append(_n) or {})
        monkeypatch.setattr(
            enrichment_jobs, "decay_ioc_confidence", lambda *a, **kw: seen.append(("decay", len(a), kw)) or {}
        )
        enrichment_jobs.run_all_enrichment_jobs(MagicMock())
        assert ("decay", 1, {}) in seen, "the client only: the job runs at the database's current time"
        assert seen.index(("decay", 1, {})) < seen.index("build_campaign_nodes")


class TestTheDagPassesNoTime:
    """2026-10-16: the aging runs at the database's current time, so no DAG task, runner or sync takes a
    time of the run (the DAG tests run the tasks: ``tests/test_sync_cadence_and_backup_gate.py``,
    ``tests/test_baseline_chain_guards.py``)."""

    def test_the_signatures_take_no_time(self):
        import inspect

        assert list(inspect.signature(enrichment_jobs.run_all_enrichment_jobs).parameters) == ["neo4j_client"]
        assert list(inspect.signature(enrichment_jobs.decay_ioc_confidence).parameters) == ["neo4j_client", "as_of"]

    def test_the_dag_reads_no_time_of_the_run_for_the_aging(self):
        source = (Path(__file__).resolve().parent.parent / "dags" / "edgeguard_pipeline.py").read_text()
        assert "as_of" not in source.lower(), "no time of the run reaches the sync or the aging job"
        assert source.count("run_all_enrichment_jobs(client)") == 2
        assert source.count("sync = MISPToNeo4jSync()") == 2


class TestTheTimeNeverMovesBackwards:
    """2026-10-16: every evaluation applies the rule at the later of its time and the node's
    ``aging_evaluated_at`` and stores that time with the aging values; the job writes only nodes whose
    values change. The Cypher runs on Neo4j in ``tests/test_indicator_aging_neo4j.py``; here, the
    fragments and a Python model of the rule show why storing the time only with a change suffices."""

    def test_the_evaluation_time_is_the_later_of_the_database_time_and_the_stored(self):
        assert ia.EVALUATED_AT == "aging_evaluated_at" and ia.DATABASE_TIME == "datetime()"
        assert ia.evaluated_at_expr("n") == (
            "CASE WHEN n.aging_evaluated_at > datetime() THEN n.aging_evaluated_at ELSE datetime() END"
        )
        body = ia.aging_map("n")
        assert body.startswith(f"[_at IN [{ia.evaluated_at_expr('n')}] | [_basis IN [")
        assert "duration.inDays(_basis, _at).days" in body
        assert body.count("datetime()") == 2, "the database's time is read only through the later-of"
        assert body.endswith(
            "aging_evaluated_at: CASE WHEN _age IS NULL THEN n.aging_evaluated_at ELSE _at END}][0]][0]][0]][0]"
        )
        job = ia.aging_map("n", enrichment_jobs.AGING_JOB_TIME)
        assert job.startswith(f"[_at IN [{ia.evaluated_at_expr('n', enrichment_jobs.AGING_JOB_TIME)}] | ")
        assert job.count(enrichment_jobs.AGING_JOB_TIME) == 2, "a test's time is lifted like the database's"

    def test_every_write_evaluates_at_the_database_time_without_a_parameter(self):
        """The writers splice ``aging_set_clause``, which reads the database's current time and no
        parameter: the batch and the single-item path in their statement, the alert path in the second
        statement of its transaction (primary and fallback)."""
        clause = ia.aging_set_clause("n")
        assert ia.evaluated_at_expr("n", ia.DATABASE_TIME) in clause
        assert "$" not in clause, "no parameter in the rule of a write"
        source = (_SRC / "neo4j_client.py").read_text()
        assert source.count('aging_set_clause("n")') == 2  # the batch and the single-item path
        assert source.count('aging_set_clause("i")') == 1  # the alert path's second statement
        for writer in ("neo4j_client.py", "run_misp_to_neo4j.py"):
            assert "as_of" not in (_SRC / writer).read_text().lower(), writer

    @staticmethod
    def _state(policy: ia.AgingPolicy, age: int) -> tuple:
        """The rule's values for one basis at an age (Python model of ``aging_map``)."""
        tier = policy.tier(age)
        retired = age >= policy.retire_days
        since = policy.retire_days if retired else policy.tier_start(tier)
        return (tier, policy.factor(tier), policy.confidence(0.8, age), since, not retired, retired)

    def test_every_value_moves_one_way_as_the_time_grows(self):
        """For one basis the values are a step function of the time that never steps back: the tier
        and ``aging_since`` only grow, the factor and the confidence only fall, a retired node stays
        retired. This is what lets an older time be lifted to the stored one."""
        p = ia.AgingPolicy()
        states = [self._state(p, age) for age in range(-5, 1200)]
        for before, after in pairwise(states):
            assert after[0] >= before[0] and after[3] >= before[3]
            assert after[1] <= before[1] and after[2] <= before[2]
            assert before[4] or not after[4]

    def test_any_order_of_evaluations_ends_in_the_latest_state_and_never_steps_back(self):
        """Model of the job: evaluate at ``max(time, stored)``, write the values and the time only when
        a value changes. Over random times in random orders the node never steps back and ends in the
        state of the latest time, although the time is stored only with a change."""
        p = ia.AgingPolicy()
        rng = random.Random(20261016)
        for _ in range(500):
            times = [rng.randrange(0, 1100) for _ in range(rng.randrange(1, 7))]
            stored_state, stored_at = None, None
            history = []
            for t in times:
                at = t if stored_at is None or t > stored_at else stored_at
                state = self._state(p, at)
                if state != stored_state:
                    stored_state, stored_at = state, at
                history.append(stored_state)
            for before, after in pairwise(history):
                assert after[0] >= before[0] and after[3] >= before[3] and (before[4] or not after[4])
            assert stored_state == self._state(p, max(times)), times

    def test_at_the_database_time_a_newer_report_is_evaluated_at_the_time_of_its_write(self):
        """Model of the 2026-10-16 decision: every evaluation runs at the database's time when it runs
        (real time, which only moves forward), lifted to the stored time; a write may bring a newer
        report (a later basis) and always writes, the job writes only on a change. After every step the
        node holds the state of its current basis at the latest time an evaluation ran at: a write of
        a newer report after a job that changed nothing evaluates at the write's own, later time."""
        p = ia.AgingPolicy()
        rng = random.Random(20261017)
        for _ in range(1000):
            clock = rng.randrange(0, 900)
            basis = clock - rng.randrange(0, 900)
            stored_state, stored_at = None, None
            for _step in range(rng.randrange(1, 9)):
                clock += rng.randrange(0, 120)
                at = clock if stored_at is None or clock > stored_at else stored_at
                if rng.random() < 0.5:  # a write; with a newer report half of the time
                    if rng.random() < 0.5:
                        basis = rng.randrange(basis, clock + 1)
                    stored_state, stored_at = self._state(p, at - basis), at
                else:  # the job
                    state = self._state(p, at - basis)
                    if state != stored_state:
                        stored_state, stored_at = state, at
                assert stored_at <= clock
                assert stored_state == self._state(p, clock - basis), (clock, basis, stored_at)

    def test_a_write_started_before_a_job_that_changed_nothing_lags_until_the_next_evaluation(self):
        """The one case the lift does not cover (``indicator_aging``, *The time of an evaluation*): the
        database reads the time once per statement, when it starts, and a job that changes nothing on a
        node neither locks it nor stores a time. A write whose statement started at ``t_w``, before such
        a job at ``t_j``, commits a newer report after it: the report is evaluated at ``t_w``, where it
        is 89 days old (no tier), although it is 90 days old (the first tier) at the job's time. The
        node moved nothing backwards, and the next evaluation, at its own time, brings it to that time."""
        p = ia.AgingPolicy()
        t_w, t_j = 1000, 1001
        old_basis, stored_at = t_j - 500, 999  # the old report: the third tier at the stored time and at t_j
        stored_state = self._state(p, stored_at - old_basis)
        at = max(t_j, stored_at)
        assert self._state(p, at - old_basis) == stored_state, "the job at t_j changes nothing and stores no time"

        new_basis = t_w - (p.tier_days[0] - 1)
        at = max(t_w, stored_at)  # the write, committed after the job, at its statement's start
        stored_state, stored_at = self._state(p, at - new_basis), at
        assert (stored_at, stored_state[0]) == (t_w, 0) and stored_at < t_j
        assert self._state(p, t_j - new_basis)[0] == 1, "at the job's time the new report is in the first tier"

        later = t_j + 1  # the next job (or write), at its own time
        at = max(later, stored_at)
        state = self._state(p, at - new_basis)
        assert state != stored_state
        stored_state, stored_at = state, at
        assert (stored_at, stored_state[0], stored_state[1]) == (later, 1, p.factor(1))

    def test_overlapping_statements_never_step_back_and_a_later_evaluation_catches_up(self):
        """Model with statement clocks: a write's statement may have started before evaluations that
        committed before it (lock waits, a long batch). Whatever the order, the node holds the state of
        its basis at its stored time, never later than the current time; for one basis it never steps
        back; and after an evaluation that started after everything committed before it, the node
        holds the state of that evaluation's own time."""
        p = ia.AgingPolicy()
        rng = random.Random(20261018)
        lagged = 0
        for _ in range(2000):
            clock = rng.randrange(0, 900)
            basis = clock - rng.randrange(0, 900)
            stored_state, stored_at = None, None
            for _step in range(rng.randrange(1, 9)):
                clock += rng.randrange(0, 60)
                write = rng.random() < 0.5
                start = clock - (rng.randrange(0, 30) if write else 0)
                at = start if stored_at is None or start > stored_at else stored_at
                before_basis, before = basis, stored_state
                if write:
                    if rng.random() < 0.5:
                        basis = rng.randrange(basis, start + 1)  # a newer report, recorded before the write
                    stored_state, stored_at = self._state(p, at - basis), at
                else:
                    state = self._state(p, at - basis)
                    if state != stored_state:
                        stored_state, stored_at = state, at
                assert stored_at <= clock
                assert stored_state == self._state(p, stored_at - basis), (clock, basis, stored_at)
                if before is not None and before_basis == basis:
                    assert stored_state[0] >= before[0] and stored_state[3] >= before[3]
                    assert before[4] or not stored_state[4], "no reactivation without a newer report"
                if start == clock:
                    assert stored_state == self._state(p, clock - basis), (clock, basis, stored_at)
                elif stored_state != self._state(p, clock - basis):
                    lagged += 1
        assert lagged, "the model reaches the lagging case it describes"


# ================================================================ the readers


class TestReaders:
    def test_rest_orders_indicators_by_report_time(self):
        import query_api

        text = (_SRC / "query_api.py").read_text()
        assert query_api._INDICATOR_RECENCY == "coalesce(n.last_reported_at, n.first_imported_at)"
        assert "ORDER BY n.last_updated DESC" not in text
        assert query_api._CDB_INDICATOR_ORDER_AND_LIMIT.startswith(
            "ORDER BY (coalesce(n.last_reported_at, n.first_imported_at) IS NULL), "
        )

    def test_the_zone_list_orders_every_label_by_one_clock(self, monkeypatch):
        """``/zone/{zone}`` lists indicators with catalogue nodes and campaigns, all by one clock: an
        Indicator's latest report, otherwise when the node entered the graph (``created_at`` for a
        Campaign, which has no ``first_imported_at``). ``last_updated`` (the last database write, moved
        by every sync and campaign rebuild) is not read: ordering the other labels by it put a node a
        sync had just rewritten above an indicator reported in the latest run. Run on a real Neo4j in
        tests/test_export_paths_neo4j.py."""
        from fastapi.testclient import TestClient

        import query_api

        assert query_api._ZONE_RECENCY == "coalesce(n.last_reported_at, n.first_imported_at, n.created_at)"
        assert "last_updated" not in query_api._ZONE_RECENCY
        seen = []

        class _Result(list):
            def single(self):
                return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

        class _Session:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def run(self, query, **params):
                seen.append(query)
                return _Result()

        class _Client:
            driver = SimpleNamespace(session=lambda **kw: _Session())

            def is_connected(self):
                return True

        monkeypatch.setattr(query_api, "neo4j_client", _Client())
        monkeypatch.setattr(query_api, "_API_KEY", None)
        assert TestClient(query_api.app).get("/zone/finance").status_code == 200
        listing = seen[0]
        assert f"WITH n, {query_api._ZONE_RECENCY} AS _recency" in listing
        assert "ORDER BY (_recency IS NULL), _recency DESC, n.uuid" in listing

    def test_rest_shows_the_source_confidence_of_an_older_node(self):
        import query_api

        class _Node(dict):
            labels = frozenset({"Indicator"})

        assert query_api._node_props(_Node(confidence_score=0.4))["source_confidence"] == 0.4
        assert query_api._node_props(_Node(confidence_score=0.4, source_confidence=0.8))["source_confidence"] == 0.8
        assert "source_confidence" not in query_api._node_props({"confidence_score": 0.4}), "not an Indicator"

    def test_graphql_exposes_the_aging(self):
        import graphql_api
        from graphql_schema import IndicatorFilter

        node = {
            "value": "203.0.113.50",
            "indicator_type": "ipv4",
            "confidence_score": 0.22,
            "active": False,
            "retired_by": "decay",
            "retired_at": "2026-06-01T00:00:00+00:00",
            "last_reported_at": "2024-06-01T00:00:00+00:00",
            "last_reported_source": "feodo_tracker",
            "last_reported_ref": "a-1",
            "source_confidence": 0.4,
            "aging_basis": "source_date",
            "aging_tier": 3,
            "aging_factor": 0.55,
            "aging_since": "2026-06-01T00:00:00+00:00",
            "aging_evaluated_at": "2026-10-16T03:00:00+00:00",
        }
        session = MagicMock()
        session.run.return_value = [{"n": node}]
        client = MagicMock()
        client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
        client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
        (ind,) = graphql_api._resolve_indicators(client, IndicatorFilter(active_only=False))
        assert (ind.last_reported_at, ind.last_reported_source, ind.last_reported_ref) == (
            "2024-06-01T00:00:00+00:00",
            "feodo_tracker",
            "a-1",
        )
        assert (ind.source_confidence, ind.aging_basis, ind.aging_tier, ind.active, ind.retired_by) == (
            0.4,
            "source_date",
            3,
            False,
            "decay",
        )
        assert ind.aging_evaluated_at == "2026-10-16T03:00:00+00:00", "the time the aging values were last written"
        older = dict(node, source_confidence=None)
        session.run.return_value = [{"n": older}]
        (ind,) = graphql_api._resolve_indicators(client, IndicatorFilter(active_only=False))
        assert ind.source_confidence == 0.22, "coalesce(source_confidence, confidence_score)"

    def test_stix_exposes_the_aging_and_dates_modified_from_it(self):
        import stix_exporter as sx

        props = {
            "value": "203.0.113.51",
            "indicator_type": "ipv4",
            "confidence_score": 0.22,
            "first_imported_at": "2026-10-14T06:40:00+00:00",
            "last_updated": "2026-10-16T03:00:00+00:00",
            "last_recorded_at": "2026-10-14T06:31:05+00:00",
            "aging_since": "2026-10-15T00:00:00+00:00",
            "last_reported_at": "2024-10-15T00:00:00+00:00",
            "last_reported_source": "feodo_tracker",
            "last_reported_ref": "a-1",
            "aging_basis": "source_date",
            "aging_tier": 3,
            "active": False,
            "retired_by": "decay",
            "tlp": "white",
        }
        sdo = sx.StixExporter(object())._indicator_sdo(props)
        assert sdo["created"] == "2026-10-14T06:40:00.000Z"
        assert sdo["modified"] == "2026-10-15T00:00:00.000Z", "aging_since, not last_updated"
        assert sdo["x_edgeguard_source_confidence"] == 0.22, "an older node: its confidence_score"
        assert sdo["x_edgeguard_last_reported_at"] == "2024-10-15T00:00:00+00:00"
        assert (sdo["x_edgeguard_aging_basis"], sdo["x_edgeguard_aging_tier"]) == ("source_date", 3)
        assert (sdo["x_edgeguard_active"], sdo["x_edgeguard_retired_by"]) == (False, "decay")
        for _, stix_key in sx._INDICATOR_AGING_FIELDS:
            assert stix_key in sx.EDGEGUARD_EXTENSION_PROPERTIES
        fresh = sx.StixExporter(object())._indicator_sdo(
            {"value": "203.0.113.52", "indicator_type": "ipv4", "first_imported_at": "2026-10-14T06:40:00+00:00"}
        )
        assert fresh["modified"] == fresh["created"], "never before created"
        # A source reports the indicator again (a later MISP record, ``last_recorded_at``) without a
        # change of tier: ``modified`` moves to that record.
        rereported = sx.StixExporter(object())._indicator_sdo(
            {
                "value": "203.0.113.53",
                "indicator_type": "ipv4",
                "first_imported_at": "2026-10-14T06:40:00+00:00",
                "aging_since": "2026-10-14T00:00:00+00:00",
                "last_recorded_at": "2026-11-02T04:10:00+00:00",
                "last_updated": "2026-11-05T03:00:00+00:00",
            }
        )
        assert rereported["modified"] == "2026-11-02T04:10:00.000Z", "last_recorded_at, the latest of the three"
