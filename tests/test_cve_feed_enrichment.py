"""FIRST EPSS enrichment job (``cve_feed_enrichment.enrich_cve_epss``).

No network, Neo4j or MISP: the feed is a small in-memory fixture, the download is monkeypatched and
the session is a recording fake. The same job on a real Neo4j: ``tests/test_cve_epss_ssvc_neo4j.py``.
"""

from __future__ import annotations

import gzip
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import config  # noqa: E402
import cve_feed_enrichment as cfe  # noqa: E402
import enrichment_jobs  # noqa: E402

# The first lines of FIRST's file of 2026-10-11, and one malformed row.
EPSS_TEXT = (
    "#model_version:v2026.06.15,score_date:2026-10-11T12:00:25Z\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.97565,0.99999\n"
    "CVE-2020-0001,0.00043,0.09500\n"
    "CVE-2019-9999,notanumber,0.5\n"
)
SCORE_DATE = "2026-10-11T12:00:25Z"
MARKER = "c.edgeguard_enriched = CASE WHEN c.edgeguard_managed = true THEN c.edgeguard_enriched ELSE true END"


class FakeSession:
    """Records every statement; answers the job's statements with the given counts."""

    def __init__(self, scored_before=0, cleared=0, cves=0, matched=None, fail_on_batch=None):
        self.calls = []
        self.scored_before, self.cleared, self.cves = scored_before, cleared, cves
        self.matched = matched  # rows matched per batch; None = every row
        self.fail_on_batch = fail_on_batch
        self.batches = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher, **params):
        self.calls.append((cypher, params))
        if "UNWIND $rows" in cypher:
            self.batches += 1
            if self.fail_on_batch == self.batches:
                raise RuntimeError("neo4j down")
            record = {"updated": len(params["rows"]) if self.matched is None else self.matched}
        elif "AS scored" in cypher:
            record = {"scored": self.scored_before}
        elif "AS cleared" in cypher:
            record = {"cleared": self.cleared}
        elif "AS cves" in cypher:
            record = {"cves": self.cves}
        else:
            raise AssertionError(f"unexpected statement: {cypher}")
        return SimpleNamespace(single=lambda: record)

    def kinds(self):
        def kind(cypher):
            for marker, name in (("UNWIND $rows", "batch"), ("AS scored", "scored"), ("AS cleared", "clear")):
                if marker in cypher:
                    return name
            return "cves"

        return [kind(c) for c, _p in self.calls]


def _client(session):
    return SimpleNamespace(driver=SimpleNamespace(session=lambda: session))


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch):
    monkeypatch.setattr(cfe, "query_pause", lambda: None)


def _feed(monkeypatch, text=EPSS_TEXT):
    monkeypatch.setattr(cfe, "fetch_epss_bytes", lambda url: gzip.compress(text.encode()))


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


class TestParse:
    def test_parse_feed(self):
        model, date, rows, skipped = cfe.parse_epss(gzip.compress(EPSS_TEXT.encode()))
        assert (model, date, skipped) == ("v2026.06.15", SCORE_DATE, 1)
        assert rows == [
            {"cve": "CVE-2021-44228", "epss": 0.97565, "percentile": 0.99999},
            {"cve": "CVE-2020-0001", "epss": 0.00043, "percentile": 0.095},
        ]

    def test_rows_outside_the_ranges_or_with_bad_ids_are_skipped(self):
        text = (
            f"#model_version:v1,score_date:{SCORE_DATE}\ncve,epss,percentile\n"
            "cve-2020-0002,0.1,0.2\n"  # read as CVE-2020-0002
            "CVE-2020-1,0.1,0.2\nCVE-2020-0003,1.5,0.2\nCVE-2020-0004,0.1,-0.1\nCVE-2020-0005\n"
        )
        _model, _date, rows, skipped = cfe.parse_epss(gzip.compress(text.encode()))
        assert [r["cve"] for r in rows] == ["CVE-2020-0002"] and skipped == 4

    @pytest.mark.parametrize(
        "raw, reason",
        [
            (b"not gzip", "not valid gzip"),
            (gzip.compress(f"#score_date:{SCORE_DATE}\ncve,epss,percentile\n".encode()), "no valid rows"),
            (gzip.compress(f"#score_date:{SCORE_DATE}\nCVE-2020-0001,0.1,0.2\n".encode()), "header"),
            (gzip.compress(b""), "header"),
            # The score date tells a current value from a stale one: no date, no clearing, no write.
            (gzip.compress(b"#model_version:v1\ncve,epss,percentile\nCVE-2020-0001,0.1,0.2\n"), "score_date"),
        ],
    )
    def test_an_unusable_feed_raises_feed_error(self, raw, reason):
        with pytest.raises(cfe.FeedError, match=reason):
            cfe.parse_epss(raw)

    def test_header_values_capped_at_64_chars(self):
        text = f"#model_version:{'v' * 100},score_date:{'d' * 100}\ncve,epss,percentile\nCVE-2020-0001,0.1,0.2\n"
        model, date, _, _ = cfe.parse_epss(gzip.compress(text.encode()))
        assert len(model) == 64 and len(date) == 64


# ---------------------------------------------------------------------------
# download bounds
# ---------------------------------------------------------------------------


def _response(chunks):
    resp = MagicMock()
    resp.iter_content.return_value = iter(chunks)
    return resp


class TestDownload:
    def test_over_cap_download_yields_skipped(self, monkeypatch):
        resp = _response([b"x" * 600, b"x" * 600])
        monkeypatch.setattr(cfe.requests, "get", lambda *a, **k: resp)
        monkeypatch.setattr(config, "EPSS_MAX_BYTES", 1000)
        session = FakeSession()
        out = cfe.enrich_cve_epss(_client(session))
        assert "exceeds cap" in out["skipped"] and session.calls == []
        resp.close.assert_called_once()  # the aborted stream releases its connection

    def test_a_download_past_the_deadline_yields_skipped(self, monkeypatch):
        # Per-read timeouts only bound a stalled connection; a trickling one is stopped by the deadline.
        clock = iter([0.0, 10.0, 400.0])
        monkeypatch.setattr(cfe, "time", SimpleNamespace(monotonic=lambda: next(clock)))
        monkeypatch.setattr(config, "EPSS_DOWNLOAD_DEADLINE_SEC", 300)
        monkeypatch.setattr(cfe.requests, "get", lambda *a, **k: _response([b"a", b"b", b"c"]))
        session = FakeSession()
        assert cfe.enrich_cve_epss(_client(session)) == {"skipped": "EPSS download exceeds 300 s"}
        assert session.calls == []

    def test_over_cap_decompressed_stream_yields_skipped(self, monkeypatch):
        bomb = gzip.compress(f"#score_date:{SCORE_DATE}\ncve,epss,percentile\n".encode() + b"0" * 5_000_000)
        monkeypatch.setattr(cfe, "fetch_epss_bytes", lambda url: bomb)
        monkeypatch.setattr(cfe, "EPSS_MAX_DECOMPRESSED_BYTES", 100_000)
        session = FakeSession()
        out = cfe.enrich_cve_epss(_client(session))
        assert "decompressed" in out["skipped"] and session.calls == []

    @pytest.mark.parametrize(
        "error", [requests.ConnectionError("down"), requests.Timeout("slow"), requests.HTTPError("503")]
    )
    def test_request_errors_become_feed_errors(self, monkeypatch, error):
        resp = _response([b"abc"])
        resp.raise_for_status.side_effect = error if isinstance(error, requests.HTTPError) else None

        def get(*a, **k):
            if not isinstance(error, requests.HTTPError):
                raise error
            return resp

        monkeypatch.setattr(cfe.requests, "get", get)
        with pytest.raises(cfe.FeedError):
            cfe.fetch_epss_bytes("http://x")

    def test_the_feed_is_returned_whole(self, monkeypatch):
        resp = _response([b"abc", b"def"])
        monkeypatch.setattr(cfe.requests, "get", lambda *a, **k: resp)
        assert cfe.fetch_epss_bytes("http://x") == b"abcdef"
        resp.close.assert_called_once()


# ---------------------------------------------------------------------------
# the job
# ---------------------------------------------------------------------------


class TestJob:
    def test_writes_existing_cves_then_clears_those_that_left_the_feed(self, monkeypatch):
        _feed(monkeypatch)
        session = FakeSession(scored_before=3, cleared=1)
        result = cfe.enrich_cve_epss(_client(session))
        assert result == {
            "rows_in_feed": 2,
            "cves_updated": 2,
            "cves_cleared": 1,
            "rows_skipped": 1,
            "score_date": SCORE_DATE,
            "model_version": "v2026.06.15",
        }
        assert session.kinds() == ["scored", "batch", "clear"]
        (batch, params), (clear, clear_params) = session.calls[1], session.calls[2]
        assert params["rows"][0] == {"cve": "CVE-2021-44228", "epss": 0.97565, "percentile": 0.99999}
        assert (params["score_date"], params["model_version"]) == (SCORE_DATE, "v2026.06.15")
        assert clear_params["score_date"] == SCORE_DATE

    def test_the_statements(self):
        batch = cfe._EPSS_CYPHER
        assert "MATCH (c:CVE {cve_id: r.cve})" in batch
        assert "MERGE" not in batch and "CREATE" not in batch, "existing CVE nodes only"
        for prop in ("epss_score", "epss_percentile", "epss_score_date", "epss_model_version", "epss_updated_at"):
            assert f"c.{prop} =" in batch
            assert f"c.{prop}" in cfe._EPSS_CLEAR_CYPHER
        # A partner's CVE node gets the shared-database marker; EdgeGuard's own keeps its value.
        assert MARKER in batch
        # Only a value from an earlier file is cleared, and only after every batch is written.
        assert "c.epss_score_date <> $score_date" in cfe._EPSS_CLEAR_CYPHER
        assert "REMOVE c.epss_score," in cfe._EPSS_CLEAR_CYPHER

    def test_batches_of_5000_and_one_clear_after_the_last(self, monkeypatch):
        body = f"#model_version:v1,score_date:{SCORE_DATE}\ncve,epss,percentile\n" + "".join(
            f"CVE-2020-{n:05d},0.1,0.2\n" for n in range(10001, 10001 + 5001)
        )
        _feed(monkeypatch, body)
        session = FakeSession(scored_before=5001)
        out = cfe.enrich_cve_epss(_client(session))
        assert session.kinds() == ["scored", "batch", "batch", "clear"]
        assert [len(p["rows"]) for c, p in session.calls if "UNWIND" in c] == [5000, 1]
        assert out["cves_updated"] == 5001

    def test_a_short_feed_clears_nothing(self, monkeypatch, caplog):
        # Two rows against 10,000 scored nodes: a truncated or wrong file must not wipe the scores.
        _feed(monkeypatch)
        session = FakeSession(scored_before=10_000, cleared=9_998)
        with caplog.at_level("WARNING", logger="cve_feed_enrichment"):
            out = cfe.enrich_cve_epss(_client(session))
        assert "clear" not in session.kinds() and out["cves_cleared"] == 0
        assert "earlier scores are kept" in caplog.text

    def test_ids_that_no_longer_match_clear_nothing(self, monkeypatch, caplog):
        # A full-size file whose ids match no node (a changed format): the row count passes any
        # threshold, the nodes matched do not, so the scores of the graph stay.
        body = f"#model_version:v1,score_date:{SCORE_DATE}\ncve,epss,percentile\n" + "".join(
            f"CVE-2020-{n:05d},0.1,0.2\n" for n in range(10001, 10001 + 5001)
        )
        _feed(monkeypatch, body)
        session = FakeSession(scored_before=4_000, matched=0, cves=4_200, cleared=4_000)
        with caplog.at_level("WARNING", logger="cve_feed_enrichment"):
            out = cfe.enrich_cve_epss(_client(session))
        assert "clear" not in session.kinds() and out["cves_cleared"] == 0
        assert "no CVE node matched" in caplog.text and "earlier scores are kept" in caplog.text

    def test_a_feed_of_half_the_scored_nodes_still_clears(self, monkeypatch):
        _feed(monkeypatch)
        session = FakeSession(scored_before=4, cleared=2)
        assert cfe.enrich_cve_epss(_client(session))["cves_cleared"] == 2

    def test_no_match_on_a_graph_with_cves_is_a_warning(self, monkeypatch, caplog):
        _feed(monkeypatch)
        session = FakeSession(matched=0, cves=140_000)
        with caplog.at_level("WARNING", logger="cve_feed_enrichment"):
            out = cfe.enrich_cve_epss(_client(session))
        assert out["cves_updated"] == 0 and "no CVE node matched" in caplog.text

    def test_no_match_on_a_graph_without_cves_is_quiet(self, monkeypatch, caplog):
        _feed(monkeypatch)
        session = FakeSession(matched=0, cves=0)
        with caplog.at_level("WARNING", logger="cve_feed_enrichment"):
            cfe.enrich_cve_epss(_client(session))
        assert "no CVE node matched" not in caplog.text

    def test_fetch_failure_returns_skipped_and_does_not_raise(self, monkeypatch):
        def boom(url):
            raise cfe.FeedError("HTTP 503")

        monkeypatch.setattr(cfe, "fetch_epss_bytes", boom)
        session = FakeSession()
        assert cfe.enrich_cve_epss(_client(session)) == {"skipped": "HTTP 503"}
        assert session.calls == []

    def test_a_failed_batch_raises_and_clears_nothing(self, monkeypatch):
        body = f"#model_version:v1,score_date:{SCORE_DATE}\ncve,epss,percentile\n" + "".join(
            f"CVE-2020-{n:05d},0.1,0.2\n" for n in range(10001, 10001 + 5001)
        )
        _feed(monkeypatch, body)
        session = FakeSession(scored_before=5001, fail_on_batch=2)
        with pytest.raises(RuntimeError):
            cfe.enrich_cve_epss(_client(session))
        assert session.kinds() == ["scored", "batch", "batch"], "a partial write never clears"


# ---------------------------------------------------------------------------
# runner wiring
# ---------------------------------------------------------------------------


def _patch_other_jobs(monkeypatch):
    for name in (
        "bridge_vulnerability_cve",
        "merge_alias_duplicate_actors",
        "build_campaign_nodes",
        "calibrate_cooccurrence_confidence",
        "decay_ioc_confidence",
    ):
        monkeypatch.setattr(enrichment_jobs, name, lambda c: {"n": 1})


class TestRunner:
    def test_six_jobs_and_the_summary_line(self, monkeypatch, caplog):
        _patch_other_jobs(monkeypatch)
        monkeypatch.setattr(config, "ENABLE_EPSS", True)
        result = {"rows_in_feed": 390_000, "cves_updated": 5, "cves_cleared": 2, "rows_skipped": 0}
        monkeypatch.setattr(enrichment_jobs, "enrich_cve_epss", lambda c: result)
        with caplog.at_level("INFO", logger="enrichment_jobs"):
            summary = enrichment_jobs.run_all_enrichment_jobs(MagicMock())
        assert set(summary) == {"bridge", "actor_alias_merge", "campaigns", "calibration", "decay", "epss"}
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "[1/6]" in text and "[6/6] EPSS" in text and "/7]" not in text
        # The CVE nodes EPSS updated, not the sum of its counts.
        assert "calibration=1 decay=1 epss=5" in text

    def test_the_flag_off_makes_no_network_call(self, monkeypatch):
        _patch_other_jobs(monkeypatch)
        monkeypatch.setattr(config, "ENABLE_EPSS", False)
        get = MagicMock(side_effect=AssertionError("network call with the flag off"))
        monkeypatch.setattr(cfe.requests, "get", get)
        client = MagicMock()
        summary = enrichment_jobs.run_all_enrichment_jobs(client)
        get.assert_not_called()
        assert summary["epss"] == {"skipped": "disabled"}
        client.driver.session.assert_not_called()

    def test_config_defaults(self):
        assert config.EPSS_URL == "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
        assert config.EPSS_MAX_BYTES == 64 * 1024 * 1024
        assert config.EPSS_DOWNLOAD_DEADLINE_SEC == 300
        assert not [name for name in dir(config) if "VULNRICHMENT" in name], "SSVC comes with the NVD records"
