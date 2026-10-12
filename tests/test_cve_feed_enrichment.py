"""EPSS + CISA Vulnrichment enrichment jobs.

No network, Neo4j or MISP: feeds are small in-memory fixtures; fetch functions are monkeypatched.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import sys
import zipfile
from unittest.mock import MagicMock

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import config  # noqa: E402
import cve_feed_enrichment as cfe  # noqa: E402
import enrichment_jobs  # noqa: E402

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

EPSS_TEXT = (
    "#model_version:v2026.06.15,score_date:2026-10-11T12:00:25Z\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.97565,0.99999\n"
    "CVE-2020-0001,0.00043,0.09500\n"
    "CVE-2019-9999,notanumber,0.5\n"
)


def _client():
    """MagicMock neo4j client whose session.run(...).single() returns a count equal to len(rows)."""
    client = MagicMock()
    session = client.driver.session.return_value.__enter__.return_value

    def _run(cypher, **kwargs):
        res = MagicMock()
        res.single.return_value = {"updated": len(kwargs.get("rows", []))}
        return res

    session.run.side_effect = _run
    return client, session


def _vr_record(cve_id, *, exploitation="active", automatable="yes", impact="total", cwe="CWE-502"):
    return json.dumps(
        {
            "cveMetadata": {"cveId": cve_id},
            "containers": {
                "cna": {"problemTypes": [{"descriptions": [{"cweId": "CWE-999"}]}]},
                "adp": [
                    {"providerMetadata": {"shortName": "CVE"}, "metrics": []},
                    {
                        "providerMetadata": {"shortName": "CISA-ADP"},
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "timestamp": "2026-01-02T03:04:05Z",
                                        "options": [
                                            {"Exploitation": exploitation},
                                            {"Automatable": automatable},
                                            {"Technical Impact": impact},
                                        ],
                                    },
                                }
                            }
                        ],
                        "problemTypes": [{"descriptions": [{"type": "CWE", "cweId": cwe}]}],
                    },
                ],
            },
        }
    )


def _zip_bytes(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------


class TestEpssParse:
    def test_parse_fixture(self):
        model, date, rows, skipped = cfe.parse_epss(gzip.compress(EPSS_TEXT.encode()))
        assert model == "v2026.06.15"
        assert date == "2026-10-11T12:00:25Z"
        assert skipped == 1
        assert rows == [
            {"cve": "CVE-2021-44228", "epss": 0.97565, "percentile": 0.99999},
            {"cve": "CVE-2020-0001", "epss": 0.00043, "percentile": 0.095},
        ]

    def test_bad_gzip_raises_feed_error(self):
        with pytest.raises(cfe.FeedError):
            cfe.parse_epss(b"not gzip")

    def test_empty_feed_raises_feed_error(self):
        with pytest.raises(cfe.FeedError):
            cfe.parse_epss(gzip.compress(b"#model_version:v1,score_date:x\ncve,epss,percentile\n"))


class TestEpssBounds:
    def test_over_cap_download_yields_skipped(self, monkeypatch):
        resp = MagicMock()
        resp.iter_content.return_value = iter([b"x" * 600, b"x" * 600])
        monkeypatch.setattr(cfe.requests, "get", lambda *a, **k: resp)
        monkeypatch.setattr(config, "EPSS_MAX_BYTES", 1000)
        client, session = _client()
        out = cfe.enrich_cve_epss(client)
        assert "skipped" in out
        session.run.assert_not_called()

    def test_over_cap_decompressed_stream_yields_skipped(self, monkeypatch):
        bomb = gzip.compress(b"#model_version:v1,score_date:d\ncve,epss,percentile\n" + b"0" * 5_000_000)
        monkeypatch.setattr(cfe, "fetch_epss_bytes", lambda url: bomb)
        monkeypatch.setattr(cfe, "EPSS_MAX_DECOMPRESSED_BYTES", 100_000)
        client, session = _client()
        out = cfe.enrich_cve_epss(client)
        assert "skipped" in out and "decompressed" in out["skipped"]
        session.run.assert_not_called()

    def test_header_values_capped_at_64_chars(self):
        text = f"#model_version:{'v' * 100},score_date:{'d' * 100}\ncve,epss,percentile\nCVE-2020-0001,0.1,0.2\n"
        model, date, _, _ = cfe.parse_epss(gzip.compress(text.encode()))
        assert len(model) == 64 and len(date) == 64


class TestEpssJob:
    def test_batch_cypher_shape_and_result(self, monkeypatch):
        monkeypatch.setattr(cfe, "fetch_epss_bytes", lambda url: gzip.compress(EPSS_TEXT.encode()))
        client, session = _client()
        result = cfe.enrich_cve_epss(client)
        assert result == {
            "rows_in_feed": 2,
            "cves_updated": 2,
            "rows_skipped": 1,
            "score_date": "2026-10-11T12:00:25Z",
            "model_version": "v2026.06.15",
        }
        cypher = session.run.call_args.args[0]
        assert "UNWIND $rows AS r" in cypher
        assert "MATCH (c:CVE {cve_id: r.cve})" in cypher
        for prop in ("epss_score", "epss_percentile", "epss_score_date", "epss_model_version", "epss_updated_at"):
            assert f"c.{prop}" in cypher
        assert "MERGE" not in cypher and "CREATE" not in cypher  # existing CVEs only
        kwargs = session.run.call_args.kwargs
        assert kwargs["score_date"] == "2026-10-11T12:00:25Z" and kwargs["model_version"] == "v2026.06.15"

    def test_batches_of_5000(self, monkeypatch):
        body = "#model_version:v1,score_date:d\ncve,epss,percentile\n" + "".join(
            f"CVE-2020-{n:05d},0.1,0.2\n" for n in range(10001, 10001 + 5001)
        )
        monkeypatch.setattr(cfe, "fetch_epss_bytes", lambda url: gzip.compress(body.encode()))
        client, session = _client()
        out = cfe.enrich_cve_epss(client)
        assert session.run.call_count == 2
        assert out["cves_updated"] == 5001

    def test_fetch_failure_returns_skipped_and_does_not_raise(self, monkeypatch):
        def boom(url):
            raise cfe.FeedError("HTTP 503")

        monkeypatch.setattr(cfe, "fetch_epss_bytes", boom)
        client, session = _client()
        assert cfe.enrich_cve_epss(client) == {"skipped": "HTTP 503"}
        session.run.assert_not_called()

    def test_fetch_wraps_request_errors(self, monkeypatch):
        import requests

        def boom(*a, **k):
            raise requests.ConnectionError("down")

        monkeypatch.setattr(cfe.requests, "get", boom)
        with pytest.raises(cfe.FeedError):
            cfe.fetch_epss_bytes("http://x")

    def test_vulnrichment_cypher_failure_raises(self, monkeypatch, tmp_path):
        z = tmp_path / "dl.zip"
        z.write_bytes(_zip_bytes({"v/2021/44xxx/CVE-2021-44228.json": _vr_record("CVE-2021-44228")}))
        monkeypatch.setattr(cfe, "download_vulnrichment_archive", lambda url, max_bytes: str(z))
        client, session = _client()

        def _run(cypher, **kwargs):
            if "RETURN c.cve_id" in cypher:
                return [{"cve_id": "CVE-2021-44228"}]
            raise RuntimeError("neo4j down")

        session.run.side_effect = _run
        with pytest.raises(RuntimeError):
            cfe.enrich_cve_vulnrichment(client)
        assert not z.exists()

    def test_cypher_failure_raises(self, monkeypatch):
        monkeypatch.setattr(cfe, "fetch_epss_bytes", lambda url: gzip.compress(EPSS_TEXT.encode()))
        client, session = _client()
        session.run.side_effect = RuntimeError("neo4j down")
        with pytest.raises(RuntimeError):
            cfe.enrich_cve_epss(client)


# ---------------------------------------------------------------------------
# Vulnrichment
# ---------------------------------------------------------------------------


class TestVulnrichmentParse:
    def test_record_extraction(self):
        rec = cfe.parse_vulnrichment_record(_vr_record("CVE-2021-44228").encode())
        assert rec == {
            "exploitation": "active",
            "automatable": "yes",
            "technical_impact": "total",
            "timestamp": "2026-01-02T03:04:05Z",
        }

    def test_record_without_adp_data_is_none(self):
        assert cfe.parse_vulnrichment_record(b'{"containers": {"adp": []}}') is None
        assert cfe.parse_vulnrichment_record(b"not json") is None

    def test_malformed_shapes_never_raise(self):
        for body in (
            b'{"containers": {"adp": [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": ["x", {"other": '
            b'{"type": "ssvc", "content": "str"}}, {"other": {"type": "ssvc", "content": {"options": "bad"}}}]}]}}',
            b'{"containers": []}',
            b"[]",
            b'{"containers": {"adp": "x"}}',
        ):
            assert cfe.parse_vulnrichment_record(body) is None

    def test_values_outside_allow_list_are_dropped(self):
        parsed = cfe.parse_vulnrichment_record(_vr_record("CVE-2021-44228", exploitation="bogus").encode())
        assert parsed["exploitation"] is None and parsed["automatable"] == "yes"
        parsed = cfe.parse_vulnrichment_record(_vr_record("CVE-2021-44228", automatable="maybe").encode())
        assert parsed["automatable"] is None and parsed["exploitation"] == "active"
        parsed = cfe.parse_vulnrichment_record(_vr_record("CVE-2021-44228", impact="huge").encode())
        assert parsed["technical_impact"] is None
        long_ts = _vr_record("CVE-2021-44228").replace("2026-01-02T03:04:05Z", "t" * 200)
        assert len(cfe.parse_vulnrichment_record(long_ts.encode())["timestamp"]) == 64

    def test_oversized_member_skipped(self, tmp_path, monkeypatch):
        z = tmp_path / "v.zip"
        z.write_bytes(_zip_bytes({"v/2021/CVE-2021-44228.json": _vr_record("CVE-2021-44228")}))
        monkeypatch.setattr(config, "VULNRICHMENT_MAX_MEMBER_BYTES", 10)
        rows, in_archive, skipped = cfe.read_vulnrichment_archive(str(z), {"CVE-2021-44228"})
        assert (rows, in_archive, skipped) == ([], 1, 1)

    def test_too_many_members_aborts(self, tmp_path, monkeypatch):
        z = tmp_path / "v.zip"
        z.write_bytes(_zip_bytes({f"v/CVE-2020-{n:04d}.json": "{}" for n in range(1000, 1005)}))
        monkeypatch.setattr(config, "VULNRICHMENT_MAX_MEMBERS", 3)
        with pytest.raises(cfe.FeedError):
            cfe.read_vulnrichment_archive(str(z), set())

    def test_archive_filters_to_graph_ids(self, tmp_path):
        z = tmp_path / "v.zip"
        z.write_bytes(
            _zip_bytes(
                {
                    "vulnrichment-develop/2021/44xxx/CVE-2021-44228.json": _vr_record("CVE-2021-44228"),
                    "vulnrichment-develop/2020/1xxx/CVE-2020-1111.json": _vr_record("CVE-2020-1111"),
                    "vulnrichment-develop/2020/2xxx/CVE-2020-2222.json": "not json",
                    "vulnrichment-develop/README.md": "hi",
                }
            )
        )
        rows, in_archive, skipped = cfe.read_vulnrichment_archive(str(z), {"CVE-2021-44228", "CVE-2020-2222"})
        assert in_archive == 3
        assert skipped == 1
        assert [r["cve"] for r in rows] == ["CVE-2021-44228"]


class TestVulnrichmentJob:
    def _setup(self, monkeypatch, tmp_path, files):
        z = tmp_path / "dl.zip"
        z.write_bytes(_zip_bytes(files))
        monkeypatch.setattr(cfe, "download_vulnrichment_archive", lambda url, max_bytes: str(z))
        client, session = _client()
        # graph id query returns two ids
        original = session.run.side_effect

        def _run(cypher, **kwargs):
            if "RETURN c.cve_id" in cypher:
                return [{"cve_id": "CVE-2021-44228"}, {"cve_id": "CVE-2019-0001"}]
            return original(cypher, **kwargs)

        session.run.side_effect = _run
        return client, session, z

    def test_job_applies_matching_record_and_deletes_temp(self, monkeypatch, tmp_path):
        client, session, z = self._setup(
            monkeypatch,
            tmp_path,
            {
                "v/2021/44xxx/CVE-2021-44228.json": _vr_record("CVE-2021-44228"),
                "v/2018/1xxx/CVE-2018-1111.json": _vr_record("CVE-2018-1111"),
            },
        )
        out = cfe.enrich_cve_vulnrichment(client)
        assert out == {"records_in_archive": 2, "records_matched": 1, "cves_updated": 1, "records_skipped": 0}
        assert not z.exists(), "temp archive must be deleted"
        write_call = [c for c in session.run.call_args_list if "UNWIND" in c.args[0]][0]
        cypher = write_call.args[0]
        assert "MATCH (c:CVE {cve_id: r.cve})" in cypher
        for prop in (
            "ssvc_exploitation",
            "ssvc_automatable",
            "ssvc_technical_impact",
            "ssvc_timestamp",
            "ssvc_updated_at",
        ):
            assert f"c.{prop}" in cypher
        # CWE is NVD-owned on a CVE node; this job must not write it
        assert "c.cwe" not in cypher
        for prop in ("ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact", "ssvc_timestamp"):
            assert f"c.{prop} = coalesce(r." in cypher
        assert "cwe" not in write_call.kwargs["rows"][0]

    def test_download_failure_returns_skipped(self, monkeypatch):
        def boom(url, max_bytes):
            raise cfe.FeedError("timeout")

        monkeypatch.setattr(cfe, "download_vulnrichment_archive", boom)
        client, session = _client()
        session.run.side_effect = lambda cypher, **k: [{"cve_id": "CVE-2021-44228"}]
        assert cfe.enrich_cve_vulnrichment(client) == {"skipped": "timeout"}

    def test_byte_cap_aborts_and_deletes_temp(self, monkeypatch):
        created = []
        real_ntf = cfe.tempfile.NamedTemporaryFile

        def ntf(*a, **k):
            f = real_ntf(*a, **k)
            created.append(f.name)
            return f

        resp = MagicMock()
        resp.iter_content.return_value = iter([b"x" * 600, b"x" * 600])
        monkeypatch.setattr(cfe.tempfile, "NamedTemporaryFile", ntf)
        monkeypatch.setattr(cfe.requests, "get", lambda *a, **k: resp)
        with pytest.raises(cfe.FeedError):
            cfe.download_vulnrichment_archive("http://x", 1000)
        assert created and not os.path.exists(created[0])

    def test_unexpected_error_mid_download_deletes_temp(self, monkeypatch):
        created = []
        real_ntf = cfe.tempfile.NamedTemporaryFile

        def ntf(*a, **k):
            f = real_ntf(*a, **k)
            created.append(f.name)
            return f

        def gen():
            yield b"abc"
            raise KeyboardInterrupt

        resp = MagicMock()
        resp.iter_content.return_value = gen()
        monkeypatch.setattr(cfe.tempfile, "NamedTemporaryFile", ntf)
        monkeypatch.setattr(cfe.requests, "get", lambda *a, **k: resp)
        with pytest.raises(KeyboardInterrupt):
            cfe.download_vulnrichment_archive("http://x", 1000)
        assert created and not os.path.exists(created[0])

    def test_download_writes_and_returns_path(self, monkeypatch):
        resp = MagicMock()
        resp.iter_content.return_value = iter([b"abc", b"def"])
        monkeypatch.setattr(cfe.requests, "get", lambda *a, **k: resp)
        path = cfe.download_vulnrichment_archive("http://x", 1000)
        try:
            assert open(path, "rb").read() == b"abcdef"
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Runner wiring
# ---------------------------------------------------------------------------


def _patch_old_jobs(monkeypatch):
    for name in (
        "bridge_vulnerability_cve",
        "merge_alias_duplicate_actors",
        "build_campaign_nodes",
        "calibrate_cooccurrence_confidence",
        "decay_ioc_confidence",
    ):
        monkeypatch.setattr(enrichment_jobs, name, lambda c: {"n": 1})


class TestRunner:
    def test_seven_jobs_and_summary_line(self, monkeypatch, caplog):
        _patch_old_jobs(monkeypatch)
        monkeypatch.setattr(config, "ENABLE_EPSS", True)
        monkeypatch.setattr(config, "ENABLE_VULNRICHMENT", True)
        monkeypatch.setattr(enrichment_jobs, "enrich_cve_epss", lambda c: {"cves_updated": 5})
        monkeypatch.setattr(enrichment_jobs, "enrich_cve_vulnrichment", lambda c: {"cves_updated": 7})
        with caplog.at_level("INFO", logger="enrichment_jobs"):
            summary = enrichment_jobs.run_all_enrichment_jobs(MagicMock())
        assert set(summary) == {
            "bridge",
            "actor_alias_merge",
            "campaigns",
            "calibration",
            "decay",
            "epss",
            "vulnrichment",
        }
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "[6/7]" in text and "[7/7]" in text and "[1/7]" in text
        assert "epss=5 vulnrichment=7" in text

    def test_flags_off_make_no_network_call(self, monkeypatch):
        _patch_old_jobs(monkeypatch)
        monkeypatch.setattr(config, "ENABLE_EPSS", False)
        monkeypatch.setattr(config, "ENABLE_VULNRICHMENT", False)
        get = MagicMock(side_effect=AssertionError("network call with flags off"))
        monkeypatch.setattr(cfe.requests, "get", get)
        client = MagicMock()
        summary = enrichment_jobs.run_all_enrichment_jobs(client)
        get.assert_not_called()
        assert summary["epss"] == {"skipped": "disabled"}
        assert summary["vulnrichment"] == {"skipped": "disabled"}
        client.driver.session.assert_not_called()

    def test_config_defaults(self):
        assert config.EPSS_URL.startswith("https://epss.cyentia.com/")
        assert config.VULNRICHMENT_ARCHIVE_URL.endswith("refs/heads/develop")
        assert config.VULNRICHMENT_MAX_BYTES == 1_500_000_000
