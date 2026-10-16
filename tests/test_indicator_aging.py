"""One aging rule for indicators, whoever supplied them (2026-10-16, ``src/indicator_aging.py``).

The owner's rule: aging depends on the kind of fact, not on who supplied it or who created the
node. Every Indicator ages from the latest report of any source (the source's own last-report
date, capped at the MISP record time; the MISP record time when the source gives none; when
EdgeGuard created the node when no report dated it), with the confidence a source gave times the
factor of the tier reached, and is retired after 730 days without a report. Nothing else ages.

These unit tests run the real callers on fixtures shaped like the MISP 2.5 attributes the sync
reads (``timestamp`` epoch strings or PyMISP datetimes, the native ``last_seen``, ``uuid``, the
source tag) and check what reaches the writer, the job's statements, the DAG's evaluation time,
the readers and the configuration. The Cypher semantics run on Neo4j in
``tests/test_indicator_aging_neo4j.py``.
"""

from __future__ import annotations

import logging
import random
import sys
from datetime import datetime, timedelta, timezone
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

    def test_the_job_reads_every_indicator_with_a_time(self):
        outer, _inner, _count = enrichment_jobs._aging_job_statements(ia.AgingPolicy())
        assert outer == (
            "MATCH (n:Indicator) WHERE coalesce(n.last_reported_at, n.first_imported_at) IS NOT NULL RETURN n"
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
        assert ia.aging_set_item("n", "datetime()") in merge.args[0]


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
    def test_it_runs_the_rule_at_the_given_time_and_reports_the_state(self, caplog):
        session = _JobSession(STATS)
        as_of = datetime(2026, 10, 16, 3, 0, tzinfo=UTC)
        with caplog.at_level(logging.INFO, logger="enrichment_jobs"):
            result = enrichment_jobs.decay_ioc_confidence(_job_client(session), as_of=as_of)
        count, iterate, stats = session.calls
        assert count[1]["as_of"] == "2026-10-16T03:00:00+00:00"
        assert iterate[1]["as_of"] == "2026-10-16T03:00:00+00:00"
        outer, inner, _ = enrichment_jobs._aging_job_statements(ia.load_aging_policy())
        assert (iterate[1]["outer"], iterate[1]["inner"]) == (outer, inner)
        assert "params: {as_of: $as_of}" in iterate[0]
        assert result["changed"] == 3
        assert result["tiers"] == {"tier_0": 6, "tier_1": 2, "tier_2": 0, "tier_3": 4}
        assert result["retired"] == 4 and result["no_time"] == 0
        assert result["by_basis"] == {"source_date": 9, "misp_recorded": 2, "first_imported": 1}
        assert "3 Indicator(s) changed" in caplog.text and "retired (from 730 d): 4" in caplog.text
        assert "first_imported=1" in caplog.text and "with no time at all: 0" in caplog.text

    def test_indicators_without_a_time_are_counted_and_warned(self, caplog):
        session = _JobSession(STATS[:1] + [{"tier": None, "basis": None, "retired": False, "no_time": True, "c": 2}])
        with caplog.at_level(logging.WARNING, logger="enrichment_jobs"):
            result = enrichment_jobs.decay_ioc_confidence(_job_client(session), as_of="2026-10-16T00:00:00Z")
        assert result["no_time"] == 2 and "neither last_reported_at nor first_imported_at" in caplog.text

    def test_a_failed_batch_fails_the_job(self):
        session = _JobSession(STATS, iterate={"failedBatches": 1, "errorMessages": {"oom": 1}})
        with pytest.raises(RuntimeError, match="AGING"):
            enrichment_jobs.decay_ioc_confidence(_job_client(session), as_of=None)

    def test_as_of_forms(self):
        assert enrichment_jobs.aging_as_of("2026-10-16T03:00:00Z") == datetime(2026, 10, 16, 3, tzinfo=UTC)
        assert enrichment_jobs.aging_as_of(datetime(2026, 10, 16, 3)) == datetime(2026, 10, 16, 3, tzinfo=UTC)
        cest = datetime(2026, 10, 16, 5, tzinfo=timezone(timedelta(hours=2)))
        assert enrichment_jobs.aging_as_of(cest) == datetime(2026, 10, 16, 3, tzinfo=UTC)
        assert type(enrichment_jobs.aging_as_of(cest)) is datetime
        assert abs(enrichment_jobs.aging_as_of(None) - datetime.now(UTC)) < timedelta(seconds=5)

    def test_the_runner_passes_one_time_and_ages_before_the_campaigns(self, monkeypatch):
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
            enrichment_jobs, "decay_ioc_confidence", lambda c, as_of=None: seen.append(("decay", as_of)) or {}
        )
        as_of = datetime(2026, 10, 16, 3, tzinfo=UTC)
        enrichment_jobs.run_all_enrichment_jobs(MagicMock(), as_of=as_of)
        assert ("decay", as_of) in seen
        assert seen.index(("decay", as_of)) < seen.index("build_campaign_nodes")


class TestTheDagTime:
    @pytest.fixture(scope="class")
    def as_of(self):
        """``enrichment_as_of`` of the DAG file loaded as an isolated module (as the DAG tests do)."""
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "_dag_module_indicator_aging", Path(__file__).resolve().parent.parent / "dags" / "edgeguard_pipeline.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.enrichment_as_of

    def test_the_data_interval_end_of_a_scheduled_run(self, as_of):
        end = datetime(2026, 10, 16, 3, tzinfo=UTC)
        assert as_of({"data_interval_end": end, "dag_run": SimpleNamespace(run_after=end + timedelta(hours=1))}) == end

    def test_run_after_of_a_manual_run(self, as_of):
        after = datetime(2026, 10, 16, 9, 12, tzinfo=UTC)
        assert as_of({"data_interval_end": None, "dag_run": SimpleNamespace(run_after=after)}) == after

    def test_now_without_either(self, as_of):
        assert abs(as_of({}) - datetime.now(UTC)) < timedelta(seconds=5)


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
