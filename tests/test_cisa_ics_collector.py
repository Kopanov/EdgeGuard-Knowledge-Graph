"""CISA ICS advisories collector (2026-10) — unit tests with mocked HTTP.

No network: every GET goes through a fake ``request_with_rate_limit_retries``
routed by URL suffix. Covers:

- parsing of a realistic CSAF 2.0 sample (item shape + key set)
- sector → zone mapping incl. "nothing mapped → global"
- multi-CVE advisories → multiple items
- malformed files are skipped AND counted, never abort the run
- baseline sanity floor raises a transient-classified error (+ metric)
- flag-off returns without a single fetch
- incremental cursor (changes.csv) advances only after a clean push
- DAG wrapper short-circuits on flag-off
- source-registry propagation (MISP tag, aliases, reliable first-seen)
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import os
import sys
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import collectors.cisa_ics_collector as mod  # noqa: E402

# Freeze the collector's clock. SAMPLE_ADVISORY is dated 2026-10-08 and the baseline window is
# 730 days: with a real clock these fixtures start failing in October 2028, and the name-date
# prefilter test flips on 1–20 January (``cutoff - 20d`` falls in the previous year). Every
# ``datetime.now()`` inside the collector module now returns the same instant.
_FROZEN_NOW = _dt.datetime(2026, 10, 10, 12, 0, tzinfo=_dt.timezone.utc)


class _FrozenDatetime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):  # noqa: D401 — datetime API
        return _FROZEN_NOW.astimezone(tz) if tz else _FROZEN_NOW.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def _freeze_collector_clock(monkeypatch):
    monkeypatch.setattr(mod, "datetime", _FrozenDatetime)


from collectors.collector_utils import TransientServerError  # noqa: E402
from resilience import CircuitBreaker  # noqa: E402

BASE = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"

# ---------------------------------------------------------------------------
# Fixture: a trimmed but realistic CSAF 2.0 advisory (shape verified 2026-10-10
# against cisagov/CSAF ``2026/icsa-26-281-01.json``).
# ---------------------------------------------------------------------------

SAMPLE_ADVISORY: Dict[str, Any] = {
    "document": {
        "category": "csaf_security_advisory",
        "csaf_version": "2.0",
        "title": "Red Lion Controls N-Tron 700 Series",
        "distribution": {"tlp": {"label": "WHITE"}},
        "notes": [
            {"category": "legal_disclaimer", "title": "Legal Notice and Terms of Use", "text": "..."},
            {"category": "summary", "title": "Advisory Summary", "text": "Successful exploitation ..."},
            {
                "category": "other",
                "title": "Critical infrastructure sectors",
                "text": "Commercial Facilities, Communications, Critical Manufacturing, Energy, Information Technology",
            },
            {"category": "other", "title": "Countries/areas deployed", "text": "Worldwide"},
        ],
        "references": [
            {"category": "self", "url": BASE + "2026/icsa-26-281-01.json"},
            {"category": "self", "url": "https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-01"},
        ],
        "tracking": {
            "id": "ICSA-26-281-01",
            "initial_release_date": "2026-10-08T06:00:00.000000Z",
            "current_release_date": "2026-10-09T06:00:00.000000Z",
        },
    },
    "product_tree": {
        "branches": [
            {
                "category": "vendor",
                "name": "Red Lion Controls",
                "branches": [
                    {
                        "category": "product_name",
                        "name": "700 Series",
                        "branches": [
                            {
                                "category": "product_version_range",
                                "name": "<=Firmware_3.11.0",
                                "product": {"name": "Red Lion Controls 700 Series: <=Firmware_3.11.0"},
                            }
                        ],
                    }
                ],
            }
        ]
    },
    "vulnerabilities": [
        {
            "cve": "CVE-2026-32645",
            "cwe": {"id": "CWE-798", "name": "Use of Hard-coded Credentials"},
            "notes": [
                {
                    "category": "summary",
                    "title": "Vulnerability Summary",
                    "text": "Default factory credentials persist.",
                },
                {"category": "details", "title": "SSVC", "text": "SSVCv2/E:N/A:N/2026-10-07T06:00:00.000000Z"},
            ],
            "scores": [
                {
                    "cvss_v3": {
                        "baseScore": 6.0,
                        "baseSeverity": "MEDIUM",
                        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
                        "version": "3.1",
                    },
                    "products": ["CSAFPID-0001"],
                }
            ],
        },
        {
            "cve": "cve-2026-39460",  # lower-case on purpose: must be upper-cased
            "cwe": {"id": "CWE-522", "name": "Insufficiently Protected Credentials"},
            "notes": [{"category": "summary", "title": "Vulnerability Summary", "text": "Plaintext passwords."}],
            "scores": [
                {
                    "cvss_v3": {
                        "baseScore": 8.1,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        "version": "3.1",
                    }
                }
            ],
        },
        {
            # No CVE id → skipped (counted), never emitted.
            "cwe": {"id": "CWE-306", "name": "Missing Authentication for Critical Function"},
            "notes": [],
        },
    ],
}

ITEM_KEYS = {
    "type",
    "cve_id",
    "description",
    "published",
    "last_modified",
    "cwe",
    "ref_tags",
    "reference_urls",
    "cpe_type",
    "result_impacts",
    "affected_products",
    "attack_vector",
    "cvss_score",
    "severity",
    "cvss_v31_data",
    "cvss_v30_data",
    "first_seen",
    "last_seen",
    "zone",
    "tag",
    "source",
    "confidence_score",
    "ics_sectors",
    "advisory_id",
    "vendor",
}


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", payload: Any = None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text else (json.dumps(payload) if payload is not None else "")
        self.headers: Dict[str, str] = {}

    def json(self) -> Any:
        if self._payload is not None:
            return self._payload
        return json.loads(self.text)


class _FakeHTTP:
    """Routes GETs by URL suffix; records every URL; raises for unknown paths (404)."""

    def __init__(self, routes: Dict[str, Any]):
        self.routes = routes
        self.calls: list[str] = []

    def __call__(self, method: str, url: str, **_kw: Any) -> _FakeResponse:
        self.calls.append(url)
        assert url.startswith(BASE), url
        name = url[len(BASE) :]
        if name not in self.routes:
            return _FakeResponse(status_code=404, text="not found")
        value = self.routes[name]
        if isinstance(value, _FakeResponse):
            return value
        if isinstance(value, str):
            return _FakeResponse(text=value)
        return _FakeResponse(payload=value)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Flag ON, fresh circuit breaker, no sleeps, no checkpoint I/O, default knobs."""
    import config

    monkeypatch.setattr(config, "ENABLE_CISA_ICS", True)
    monkeypatch.setattr(mod, "CISA_ICS_CIRCUIT_BREAKER", CircuitBreaker("cisa_ics_test", failure_threshold=3))
    monkeypatch.setattr(mod.CISA_ICS_RATE_LIMITER, "wait_if_needed", lambda: None)
    monkeypatch.setattr("collectors.collector_utils.time.sleep", lambda _s: None)
    monkeypatch.setattr(mod, "CISA_ICS_MAX_ADVISORIES_PER_RUN", 1200)
    monkeypatch.setattr(mod, "CISA_ICS_MIN_EXPECTED_ADVISORIES", 50)
    monkeypatch.setattr(mod, "get_source_incremental", lambda _s: {})
    monkeypatch.setattr(mod, "update_source_incremental", MagicMock())
    yield


def _collector(http: _FakeHTTP, monkeypatch, push_ok: int = 0, push_failed: int = 0) -> mod.CISAICSCollector:
    monkeypatch.setattr(mod, "request_with_rate_limit_retries", http)
    writer = MagicMock()
    writer.push_items.return_value = (push_ok, push_failed)
    c = mod.CISAICSCollector(misp_writer=writer)
    assert c.base_url == BASE
    return c


def _index(*paths: str) -> str:
    return "\n".join(paths) + "\n"


def _changes(*rows: tuple[str, str]) -> str:
    return "".join(f'"{p}","{ts}"\n' for p, ts in rows)


# ---------------------------------------------------------------------------
# Parsing + item shape
# ---------------------------------------------------------------------------


def test_parse_realistic_sample_yields_items_with_expected_shape():
    c = mod.CISAICSCollector(misp_writer=MagicMock())
    items, skipped = c.parse_advisory(copy.deepcopy(SAMPLE_ADVISORY), "2026/icsa-26-281-01.json")

    assert skipped == 1, "the CVE-less vulnerability must be skipped and counted"
    assert [i["cve_id"] for i in items] == ["CVE-2026-32645", "CVE-2026-39460"]
    first = items[0]
    assert ITEM_KEYS <= set(first), f"missing keys: {ITEM_KEYS - set(first)}"

    assert first["type"] == "vulnerability"
    assert first["tag"] == "cisa_ics" and first["source"] == ["cisa_ics"]
    assert first["confidence_score"] == 0.9
    assert first["description"].startswith("ICSA-26-281-01: Red Lion Controls N-Tron 700 Series")
    assert "Default factory credentials persist." in first["description"]
    # Source-asserted sector: only "Energy" maps → ["energy"]; raw list preserved.
    assert first["zone"] == ["energy"]
    assert first["ics_sectors"] == [
        "Commercial Facilities",
        "Communications",
        "Critical Manufacturing",
        "Energy",
        "Information Technology",
    ]
    assert first["advisory_id"] == "ICSA-26-281-01"
    assert first["vendor"] == "Red Lion Controls"
    assert first["affected_products"] == ["Red Lion Controls 700 Series"]
    assert first["cwe"] == ["CWE-798"]
    assert first["reference_urls"] == ["https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-01"]
    # Timestamps: initial → published/first_seen, current → last_modified/last_seen (ISO, tz-aware).
    assert first["published"] == first["first_seen"]
    assert first["last_modified"] == first["last_seen"]
    assert first["first_seen"].startswith("2026-10-08T06:00:00")
    assert first["last_seen"].startswith("2026-10-09T06:00:00")
    assert "+00:00" in first["first_seen"] or first["first_seen"].endswith("Z")
    # CVSS from the CSAF score block, NVD-shaped payload for the CVSSv31 sub-node.
    assert first["cvss_score"] == 6.0 and first["severity"] == "MEDIUM"
    assert first["attack_vector"] == "LOCAL"
    assert first["cvss_v30_data"] is None
    v31 = first["cvss_v31_data"]
    assert v31["vector_string"] == "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N"
    assert v31["attack_vector"] == "LOCAL" and v31["privileges_required"] == "HIGH"
    assert v31["base_score"] == 6.0 and v31["base_severity"] == "MEDIUM"
    assert first["result_impacts"] == ["HIGH", "HIGH", "NONE"]
    # Second item: lower-case CVE upper-cased, NETWORK vector.
    assert items[1]["attack_vector"] == "NETWORK" and items[1]["severity"] == "HIGH"
    # Never wall-clock: timestamps must come from the advisory, not now().
    assert "last_updated" not in first


def test_timestamps_omitted_when_advisory_has_no_dates():
    data = copy.deepcopy(SAMPLE_ADVISORY)
    data["document"]["tracking"] = {"id": "ICSA-26-281-01"}
    c = mod.CISAICSCollector(misp_writer=MagicMock())
    items, _ = c.parse_advisory(data, "2026/icsa-26-281-01.json")
    for key in ("published", "last_modified", "first_seen", "last_seen"):
        assert key not in items[0], f"{key} must be omitted (honest-NULL), not wall-clock"


def test_no_cvss_block_uses_kev_consistent_defaults_and_url_is_derived():
    data = copy.deepcopy(SAMPLE_ADVISORY)
    data["document"]["references"] = []
    data["document"]["tracking"]["id"] = "ICSMA-26-223-02"
    for v in data["vulnerabilities"]:
        v.pop("scores", None)
    c = mod.CISAICSCollector(misp_writer=MagicMock())
    items, _ = c.parse_advisory(data, "2026/icsma-26-223-02.json")
    assert items[0]["severity"] == "HIGH" and items[0]["cvss_score"] == 7.0
    assert items[0]["attack_vector"] == "NETWORK"
    assert items[0]["cvss_v31_data"] is None and items[0]["cvss_v30_data"] is None
    assert items[0]["reference_urls"] == ["https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-223-02"]


def test_unknown_advisory_id_falls_back_to_raw_github_url():
    data = copy.deepcopy(SAMPLE_ADVISORY)
    data["document"]["references"] = []
    data["document"]["tracking"]["id"] = "WEIRD-ID"
    c = mod.CISAICSCollector(misp_writer=MagicMock())
    items, _ = c.parse_advisory(data, "2026/weird.json")
    assert items[0]["reference_urls"] == [BASE + "2026/weird.json"]


# ---------------------------------------------------------------------------
# Sector → zone mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sectors, expected",
    [
        (["Energy"], ["energy"]),
        (["Healthcare and Public Health"], ["healthcare"]),
        (["Financial Services"], ["finance"]),
        (["Energy", "Financial Services", "Healthcare and Public Health"], ["energy", "finance", "healthcare"]),
        (["Critical Manufacturing", "Water and Wastewater Systems"], ["global"]),
        ([], ["global"]),
        (["  energy ", "ENERGY"], ["energy"]),  # case/whitespace tolerant, deduplicated
        (["Energy Services"], ["global"]),  # not an exact table entry → nothing
    ],
)
def test_sector_zone_mapping_table(sectors, expected):
    from config import VALID_ZONES

    zones = mod.map_sectors_to_zones(sectors)
    assert zones == expected
    assert set(zones) <= VALID_ZONES


def test_sector_table_is_exactly_the_three_specified_entries():
    assert mod.ICS_SECTOR_ZONE_MAP == {
        "Energy": "energy",
        "Healthcare and Public Health": "healthcare",
        "Financial Services": "finance",
    }


def test_keyword_sector_detector_is_not_used():
    """Sector is source-asserted: the module must not import/call the keyword detector."""
    import inspect

    src = inspect.getsource(mod)
    assert "detect_zones_from_text" not in src.replace("NOT applied", "").split("Safety contract")[1]


# ---------------------------------------------------------------------------
# Multi-CVE, malformed files, limits (baseline run through collect())
# ---------------------------------------------------------------------------


def test_multi_cve_advisory_produces_multiple_items_and_malformed_files_are_counted(monkeypatch):
    http = _FakeHTTP(
        {
            "index.txt": _index(
                "2026/icsa-26-281-01.json",
                "2026/not-an-object.json",
                "2026/no-vulns.json",
                "2026/bad-json.json",
                "2026/missing.json",  # 404
                "2025/icsa-25-010-01.json",
            ),
            "2026/icsa-26-281-01.json": copy.deepcopy(SAMPLE_ADVISORY),
            "2026/not-an-object.json": ["this", "is", "a", "list"],
            "2026/no-vulns.json": {"document": {"title": "x"}},
            "2026/bad-json.json": _FakeResponse(text="{not json"),
            "2025/icsa-25-010-01.json": copy.deepcopy(SAMPLE_ADVISORY),
        }
    )
    c = _collector(http, monkeypatch)
    items = c.collect(push_to_misp=False, baseline=True, baseline_days=730)

    # Two good advisories × 2 valid CVEs each.
    assert len(items) == 4
    assert {i["cve_id"] for i in items} == {"CVE-2026-32645", "CVE-2026-39460"}
    # Nothing aborted: every candidate was attempted exactly once.
    assert sum(1 for u in http.calls if u.endswith(".json")) == 6

    # Same run with push: status dict carries the counters.
    http.calls.clear()
    c = _collector(http, monkeypatch, push_ok=4)
    st = c.collect(push_to_misp=True, baseline=True, baseline_days=730)
    assert st["success"] is True and st["count"] == 4 and st["source"] == "cisa_ics"
    assert st["stats"]["malformed"] == 2
    assert st["stats"]["fetch_failed"] == 2  # bad JSON + 404
    assert st["stats"]["parsed_ok"] == 2
    assert st["stats"]["attempted"] == 6
    assert st["stats"]["skipped_vulns"] == 2
    c.misp_writer.push_items.assert_called_once()
    pushed = c.misp_writer.push_items.call_args[0][0]
    assert all(p["tag"] == "cisa_ics" for p in pushed)


def test_baseline_filters_by_initial_release_date_and_index_year_window(monkeypatch):
    old = copy.deepcopy(SAMPLE_ADVISORY)
    old["document"]["tracking"]["initial_release_date"] = "2019-01-01T00:00:00.000000Z"
    old["document"]["tracking"]["current_release_date"] = "2019-01-01T00:00:00.000000Z"
    http = _FakeHTTP(
        {
            "index.txt": _index(
                "2026/icsa-26-281-01.json", "2026/old-but-listed-in-2026.json", "2010/icsa-10-322-01.json"
            ),
            "2026/icsa-26-281-01.json": copy.deepcopy(SAMPLE_ADVISORY),
            "2026/old-but-listed-in-2026.json": old,
            "2010/icsa-10-322-01.json": copy.deepcopy(SAMPLE_ADVISORY),
        }
    )
    c = _collector(http, monkeypatch)
    items = c.collect(push_to_misp=False, baseline=True, baseline_days=730)
    assert len(items) == 2
    # 2010 file is outside the year window → never fetched; the stale 2026 file is fetched then dropped.
    assert not any(u.endswith("2010/icsa-10-322-01.json") for u in http.calls)
    assert any(u.endswith("2026/old-but-listed-in-2026.json") for u in http.calls)


def test_limit_caps_items_and_stops_fetching(monkeypatch):
    routes: Dict[str, Any] = {"index.txt": _index(*[f"2026/a{i:02d}.json" for i in range(10)])}
    for i in range(10):
        routes[f"2026/a{i:02d}.json"] = copy.deepcopy(SAMPLE_ADVISORY)
    http = _FakeHTTP(routes)
    c = _collector(http, monkeypatch)
    items = c.collect(limit=3, push_to_misp=False, baseline=True, baseline_days=730)
    assert len(items) == 3
    assert sum(1 for u in http.calls if u.endswith(".json")) == 2  # 2 advisories × 2 CVEs ≥ 3


def test_max_advisories_per_run_cap_applies(monkeypatch):
    monkeypatch.setattr(mod, "CISA_ICS_MAX_ADVISORIES_PER_RUN", 2)
    routes: Dict[str, Any] = {"index.txt": _index(*[f"2026/a{i:02d}.json" for i in range(5)])}
    for i in range(5):
        routes[f"2026/a{i:02d}.json"] = copy.deepcopy(SAMPLE_ADVISORY)
    http = _FakeHTTP(routes)
    c = _collector(http, monkeypatch)
    c.collect(push_to_misp=False, baseline=True, baseline_days=730)
    assert sum(1 for u in http.calls if u.endswith(".json")) == 2


# ---------------------------------------------------------------------------
# Baseline sanity floor
# ---------------------------------------------------------------------------


def test_baseline_floor_raises_transient_error_and_records_metric(monkeypatch):
    monkeypatch.setattr(mod, "CISA_ICS_MIN_EXPECTED_ADVISORIES", 10)
    routes: Dict[str, Any] = {"index.txt": _index(*[f"2026/a{i:02d}.json" for i in range(12)])}
    for i in range(12):
        routes[f"2026/a{i:02d}.json"] = copy.deepcopy(SAMPLE_ADVISORY) if i < 4 else {"document": {}}  # 8 malformed
    http = _FakeHTTP(routes)
    c = _collector(http, monkeypatch, push_ok=99)

    record = MagicMock()
    with patch.dict(sys.modules, {"metrics_server": MagicMock(record_pipeline_error=record)}):
        with pytest.raises(mod.CISAICSBaselineFloorError) as excinfo:
            c.collect(push_to_misp=True, baseline=True, baseline_days=730)

    assert "4 of 12" in str(excinfo.value)
    record.assert_called_once_with("collect_cisa_ics", "CISAICSBaselineFloorError", "cisa_ics")
    c.misp_writer.push_items.assert_not_called()

    # Classified transient by the shared DAG/CLI classifier → skip + alert, not a hard failure.
    from collector_failure_alerts import is_transient_external_error

    assert isinstance(excinfo.value, TransientServerError)
    assert is_transient_external_error(excinfo.value)


def test_baseline_floor_raises_when_index_window_is_empty(monkeypatch):
    http = _FakeHTTP({"index.txt": _index("2010/icsa-10-322-01.json")})
    c = _collector(http, monkeypatch)
    with pytest.raises(mod.CISAICSBaselineFloorError, match="0 advisories"):
        c.collect(push_to_misp=True, baseline=True, baseline_days=730)


def test_baseline_floor_not_applied_below_attempt_threshold(monkeypatch):
    """A tiny collection_limit smoke run must not trip the floor."""
    monkeypatch.setattr(mod, "CISA_ICS_MIN_EXPECTED_ADVISORIES", 10)
    http = _FakeHTTP(
        {
            "index.txt": _index("2026/a.json", "2026/b.json"),
            "2026/a.json": copy.deepcopy(SAMPLE_ADVISORY),
            "2026/b.json": {"document": {}},
        }
    )
    c = _collector(http, monkeypatch, push_ok=2)
    st = c.collect(push_to_misp=True, baseline=True, baseline_days=730)
    assert st["success"] is True and st["count"] == 2


def test_incremental_mode_never_applies_the_floor(monkeypatch):
    monkeypatch.setattr(mod, "CISA_ICS_MIN_EXPECTED_ADVISORIES", 1)
    http = _FakeHTTP({"changes.csv": ""})
    c = _collector(http, monkeypatch)
    st = c.collect(push_to_misp=True, baseline=False)
    assert st["success"] is True and st["count"] == 0 and "skipped" not in st


# ---------------------------------------------------------------------------
# Flag-off + transient upstream behaviour
# ---------------------------------------------------------------------------


def test_flag_off_returns_without_fetching(monkeypatch):
    import config

    monkeypatch.setattr(config, "ENABLE_CISA_ICS", False)
    http = _FakeHTTP({"index.txt": _index("2026/a.json"), "2026/a.json": copy.deepcopy(SAMPLE_ADVISORY)})
    c = _collector(http, monkeypatch, push_ok=5)

    st = c.collect(push_to_misp=True, baseline=True, baseline_days=730)
    assert st["success"] is True and st["count"] == 0 and st["skipped"] is True
    assert st["skip_reason_class"] == "cisa_ics_disabled_by_flag"
    assert "disabled by flag" in st["skip_reason"]
    assert c.collect(push_to_misp=False) == []
    assert http.calls == [], "flag-off must not issue a single HTTP request"
    c.misp_writer.push_items.assert_not_called()


def test_flag_defaults_off_in_config():
    """``EDGEGUARD_ENABLE_CISA_ICS`` unset → False (the collector is dormant by default)."""
    import importlib

    import config

    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("EDGEGUARD_ENABLE_CISA_ICS", None)
        fresh = importlib.reload(config)
        try:
            assert fresh.ENABLE_CISA_ICS is False
            assert fresh.CISA_ICS_MAX_ADVISORIES_PER_RUN == 1200
            assert fresh.CISA_ICS_MIN_EXPECTED_ADVISORIES == 50
            assert fresh.CISA_ICS_BASE_URL.endswith("/OT/white/")
        finally:
            importlib.reload(config)


def test_index_5xx_propagates_as_transient_even_when_pushing(monkeypatch):
    http = _FakeHTTP({"index.txt": _FakeResponse(status_code=503, text="down")})
    c = _collector(http, monkeypatch)
    with pytest.raises(TransientServerError):
        c.collect(push_to_misp=True, baseline=True, baseline_days=730)
    c.misp_writer.push_items.assert_not_called()


def test_index_404_returns_failed_status_when_pushing(monkeypatch):
    http = _FakeHTTP({})
    c = _collector(http, monkeypatch)
    st = c.collect(push_to_misp=True, baseline=True, baseline_days=730)
    assert st["success"] is False and st["count"] == 0 and "404" in st["error"]
    with pytest.raises(Exception):  # noqa: B017 - push_to_misp=False must re-raise, not return []
        c.collect(push_to_misp=False, baseline=True, baseline_days=730)


def test_consecutive_fetch_failures_abort_before_push(monkeypatch):
    monkeypatch.setattr(mod, "MAX_CONSECUTIVE_FETCH_FAILURES", 3)
    http = _FakeHTTP({"index.txt": _index(*[f"2026/a{i:02d}.json" for i in range(6)])})  # every file 404s
    c = _collector(http, monkeypatch, push_ok=1)
    with pytest.raises(mod.CISAICSTransientError, match="consecutive"):
        c.collect(push_to_misp=True, baseline=True, baseline_days=730)
    assert sum(1 for u in http.calls if u.endswith(".json")) == 3
    c.misp_writer.push_items.assert_not_called()


def test_code_defect_is_reraised_not_masked(monkeypatch):
    http = _FakeHTTP({"index.txt": _index("2026/a.json"), "2026/a.json": copy.deepcopy(SAMPLE_ADVISORY)})
    c = _collector(http, monkeypatch)
    monkeypatch.setattr(c, "parse_advisory", MagicMock(side_effect=TypeError("real bug")))
    with pytest.raises(TypeError, match="real bug"):
        c.collect(push_to_misp=True, baseline=True, baseline_days=730)


# ---------------------------------------------------------------------------
# Incremental mode (changes.csv + cursor)
# ---------------------------------------------------------------------------


def test_incremental_uses_changes_csv_and_advances_cursor_only_after_clean_push(monkeypatch):
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    recent = (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    newer = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    stale = "2017-01-12T00:00:00.000000Z"
    http = _FakeHTTP(
        {
            "changes.csv": _changes(
                ("2026/b.json", newer),
                ("2026/a.json", recent),
                ("2017/icsa-17-012-02.json", stale),
            ),
            "2026/a.json": copy.deepcopy(SAMPLE_ADVISORY),
            "2026/b.json": copy.deepcopy(SAMPLE_ADVISORY),
        }
    )
    # No cursor stored → 30-day lookback selects a + b, not the 2017 row.
    c = _collector(http, monkeypatch, push_ok=4)
    st = c.collect(push_to_misp=True, baseline=False)
    assert st["success"] is True and st["count"] == 4
    fetched = [u[len(BASE) :] for u in http.calls if u.endswith(".json")]
    assert fetched == ["2026/a.json", "2026/b.json"], "oldest-first so a capped run advances safely"
    assert not any("index.txt" in u for u in http.calls)
    mod.update_source_incremental.assert_called_once_with("cisa_ics", cisa_ics_last_change_ts=newer)

    # Dirty push (failed > 0) → cursor NOT advanced.
    mod.update_source_incremental.reset_mock()
    http.calls.clear()
    c = _collector(http, monkeypatch, push_ok=3, push_failed=1)
    c.collect(push_to_misp=True, baseline=False)
    mod.update_source_incremental.assert_not_called()

    # push_to_misp=False → nothing written to MISP → cursor NOT advanced.
    c = _collector(http, monkeypatch)
    c.collect(push_to_misp=False, baseline=False)
    mod.update_source_incremental.assert_not_called()


def test_incremental_cursor_filters_with_overlap(monkeypatch):
    monkeypatch.setattr(
        mod, "get_source_incremental", lambda _s: {"cisa_ics_last_change_ts": "2026-10-08T06:00:00.000000Z"}
    )
    http = _FakeHTTP(
        {
            "changes.csv": _changes(
                ("2026/new.json", "2026-10-09T06:00:00.000000Z"),
                ("2026/edge.json", "2026-10-07T12:00:00.000000Z"),  # inside 24h overlap → re-fetched
                ("2026/old.json", "2026-10-01T06:00:00.000000Z"),
            ),
            "2026/new.json": copy.deepcopy(SAMPLE_ADVISORY),
            "2026/edge.json": copy.deepcopy(SAMPLE_ADVISORY),
            "2026/old.json": copy.deepcopy(SAMPLE_ADVISORY),
        }
    )
    c = _collector(http, monkeypatch)
    items = c.collect(push_to_misp=False, baseline=False)
    fetched = sorted(u[len(BASE) :] for u in http.calls if u.endswith(".json"))
    assert fetched == ["2026/edge.json", "2026/new.json"]
    assert len(items) == 4


def test_parse_changes_and_index_are_defensive():
    assert mod.parse_index("2026/a.json\n\ngarbage line\n../etc/passwd.json\n2025/b.json\n2026/a.json\n") == [
        "2026/a.json",
        "2025/b.json",
    ]
    rows = mod.parse_changes('"2026/a.json","2026-10-08T06:00:00.000000Z"\n"junk"\n"2026/b.json","not a date"\n')
    assert rows == [("2026/a.json", "2026-10-08T06:00:00.000000Z")]


# ---------------------------------------------------------------------------
# Health check + registry + DAG wrapper
# ---------------------------------------------------------------------------


def test_health_check_shape(monkeypatch):
    c = mod.CISAICSCollector(misp_writer=MagicMock())
    with patch(
        "collectors.cisa_ics_collector.requests.get", return_value=_FakeResponse(status_code=200, text="x")
    ) as g:
        out = c.health_check()
    assert out["healthy"] is True and out["status_code"] == 200
    assert g.call_args[0][0] == BASE + "index.txt"
    with patch("collectors.cisa_ics_collector.requests.get", return_value=_FakeResponse(status_code=500, text="x")):
        assert c.health_check()["healthy"] is False


def test_source_registry_entry_propagates():
    from collectors.misp_writer import MISPWriter
    from neo4j_client import SOURCES
    from source_registry import get_source
    from source_truthful_timestamps import is_reliable_first_seen_source

    src = get_source("cisa_ics")
    assert src is not None and src.canonical_id == "cisa_ics"
    assert get_source("cisa-ics") is src and get_source("ics_advisories") is src
    assert src.misp_tag == "source:CISA-ICS" and src.cli_default_enabled is False
    assert MISPWriter.SOURCE_TAGS["cisa_ics"] == "source:CISA-ICS"
    assert SOURCES["cisa_ics"] == {"name": "CISA ICS Advisories", "type": "advisory", "reliability": 0.9}
    assert is_reliable_first_seen_source("cisa_ics")


def test_misp_writer_builds_vulnerability_attribute_with_ics_tags():
    from collectors.misp_writer import MISPWriter

    c = mod.CISAICSCollector(misp_writer=MagicMock())
    items, _ = c.parse_advisory(copy.deepcopy(SAMPLE_ADVISORY), "2026/icsa-26-281-01.json")
    w = MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)
    attr = w.create_vulnerability_attribute(items[0])
    assert attr is not None and attr["value"] == "CVE-2026-32645"
    tag_names = [t["name"] for t in attr["Tag"]]
    assert "source:CISA-ICS" in tag_names and "zone:Energy" in tag_names
    assert "CISA-KEV" not in tag_names, "ICS advisories must not be mislabelled as KEV"
    assert attr["comment"].startswith("NVD_META:")
    meta = json.loads(attr["comment"][len("NVD_META:") :])
    assert meta["cwe"] == ["CWE-798"] and meta["cvss_v31_data"]["base_score"] == 6.0
    assert meta["published"].startswith("2026-10-08")
    assert attr["first_seen"].startswith("2026-10-08") and attr["last_seen"].startswith("2026-10-09")


def _import_dag_module():
    for key in list(sys.modules):
        if (
            key == "edgeguard_pipeline"
            or key.startswith("airflow")
            or key == "opentelemetry"
            or key.startswith("opentelemetry.")
        ):
            del sys.modules[key]
    dags = os.path.join(os.path.dirname(__file__), "..", "dags")
    if dags not in sys.path:
        sys.path.insert(0, dags)
    import importlib

    return importlib.import_module("edgeguard_pipeline")


def test_dag_wrapper_flag_off_returns_skipped_without_running_collector(monkeypatch):
    try:
        ep = _import_dag_module()
    except Exception:
        pytest.skip("Airflow not installed in this test env")
    import config

    monkeypatch.setattr(config, "ENABLE_CISA_ICS", False)
    with patch.object(ep, "run_collector_with_metrics", MagicMock()) as run:
        st = ep.run_cisa_ics_collection()
    run.assert_not_called()
    assert st["success"] is True and st["count"] == 0 and st["skipped"] is True
    assert st["skip_reason_class"] == "cisa_ics_disabled_by_flag"


def test_dag_wrapper_flag_on_goes_through_run_collector_with_metrics(monkeypatch):
    try:
        ep = _import_dag_module()
    except Exception:
        pytest.skip("Airflow not installed in this test env")
    import config

    monkeypatch.setattr(config, "ENABLE_CISA_ICS", True)
    with (
        patch.object(ep, "run_collector_with_metrics", MagicMock(return_value={"success": True, "count": 0})) as run,
        patch("collectors.misp_writer.MISPWriter", MagicMock()),
    ):
        ep.run_cisa_ics_collection()
    assert run.call_args[0][0] == "cisa_ics"
    assert run.call_args[0][1] is mod.CISAICSCollector


def test_daily_dag_wires_the_task_next_to_mitre():
    dag_path = os.path.join(os.path.dirname(__file__), "..", "dags", "edgeguard_pipeline.py")
    with open(dag_path) as fh:
        src = fh.read()
    assert 'task_id="collect_cisa_ics"' in src
    assert "python_callable=run_cisa_ics_collection" in src
    daily = src[src.find('"edgeguard_daily"') :]
    fanout = daily[daily.find("misp_health_daily\n    >> [") : daily.find("log_daily_summary\n)")]
    assert "collect_mitre_daily," in fanout and "collect_cisa_ics_daily," in fanout
    assert "CISA ICS Advisories" in daily[: daily.find("log_daily_summary\n)")]


def test_allowlist_knows_the_collector():
    from collector_allowlist import COLLECT_SOURCES_CANONICAL

    assert "cisa_ics" in COLLECT_SOURCES_CANONICAL


# ---------------------------------------------------------------------------
# File-name date pre-filter + timestamp normalisation
# ---------------------------------------------------------------------------


def test_path_published_date_decodes_day_of_year():
    from datetime import datetime, timezone

    assert mod.path_published_date("2026/icsa-26-281-01.json") == datetime(2026, 10, 8, tzinfo=timezone.utc)
    assert mod.path_published_date("2025/icsma-25-010-01.json") == datetime(2025, 1, 10, tzinfo=timezone.utc)
    assert mod.path_published_date("2010/icsa-10-316-01a.json") == datetime(2010, 11, 12, tzinfo=timezone.utc)
    assert mod.path_published_date("2016/icsa-16-231-01-0.json") == datetime(2016, 8, 18, tzinfo=timezone.utc)
    assert mod.path_published_date("2026/a00.json") is None
    assert mod.path_published_date("2026/icsa-26-999-01.json") is not None  # overflow handled by timedelta


def test_timestamps_normalised_to_tz_aware_iso():
    data = copy.deepcopy(SAMPLE_ADVISORY)
    c = mod.CISAICSCollector(misp_writer=MagicMock())
    items, _ = c.parse_advisory(data, "2026/icsa-26-281-01.json")
    assert items[0]["first_seen"] == "2026-10-08T06:00:00+00:00"
    assert items[0]["last_seen"] == "2026-10-09T06:00:00+00:00"
    assert mod._iso_utc("2026-10-08") == "2026-10-08T00:00:00+00:00"  # date-only via coerce_iso fallback
    assert mod._iso_utc(None) is None and mod._iso_utc("") is None


def test_baseline_prefilter_skips_files_whose_name_date_is_far_before_cutoff(monkeypatch):
    from datetime import datetime, timedelta, timezone

    now = mod.datetime.now(timezone.utc)  # the frozen clock the collector sees
    cutoff = now - timedelta(days=730)

    def _name(dt: datetime, n: int = 1) -> str:
        return f"{dt.year}/icsa-{dt.year % 100:02d}-{dt.timetuple().tm_yday:03d}-{n:02d}.json"

    recent = _name(now - timedelta(days=10))
    edge = _name(cutoff - timedelta(days=20))  # inside the 45-day margin → fetched, then date-filtered
    ancient = _name(cutoff - timedelta(days=200), 2)  # same year as cutoff but far before it → never fetched
    unknown = f"{now.year}/odd-name.json"  # unparseable name → fetched, decided by initial_release_date

    def _adv(days_ago: int) -> Dict[str, Any]:
        d = copy.deepcopy(SAMPLE_ADVISORY)
        ts = (now - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
        d["document"]["tracking"]["initial_release_date"] = ts
        d["document"]["tracking"]["current_release_date"] = ts
        return d

    http = _FakeHTTP(
        {
            "index.txt": _index(ancient, edge, unknown, recent),
            recent: _adv(10),
            edge: _adv(750),
            ancient: _adv(930),
            unknown: _adv(5),
        }
    )
    c = _collector(http, monkeypatch)
    items = c.collect(push_to_misp=False, baseline=True, baseline_days=730)
    fetched = [u[len(BASE) :] for u in http.calls if u.endswith(".json")]
    assert ancient not in fetched, "file-name date far before the cutoff must not be fetched"
    assert fetched[:2] == [recent, edge], "dated files newest-first, undated files last"
    assert fetched[2] == unknown
    assert {i["advisory_id"] for i in items} and len(items) == 4  # recent + unknown; edge dropped by date filter
