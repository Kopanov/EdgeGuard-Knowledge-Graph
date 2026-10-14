"""NVD and OTX keep every record their request returns, whatever its age (2026-10).

Both collectors filtered records after the fetch by a "sector time range": the source's
publication timestamp against a timezone-aware cutoff 24 months back (``SECTOR_TIME_RANGES``).
NVD CVE API 2.0 and OTX send their timestamps without a zone (NVD ``published``
"2021-12-10T10:15:09.143", OTX ``created`` "2023-01-25T11:11:02.458000"; both checked against the
live APIs on 2026-10-14), so the comparison raised ``TypeError``, the surrounding ``except``
swallowed it, and since v2026.3.28 the filter had not dropped a real record — only test records
written with a ``Z``.

The filter is removed, not repaired. What a run collects is decided by its request: a baseline's
publication windows of ``baseline_days`` (plus the NVD KEV sweep and named ids, whatever their
age), NVD's lastMod window with newest-first selection, OTX's ``modified_since``. A working filter
would have cut the oldest hours of every baseline and any baseline longer than 24 months, dropped
the older records of the NVD KEV sweep unless exempted, and dropped OTX pulses created long ago
that are still updated, such as the real pulse below (created 2023-01-25, modified 2026-10-13; 42
of its 93 IOCs were added within the last 24 months).

The tests pin that an old record is kept, with the zone-less timestamp the source sends and with
a zoned one, so an age filter cannot come back silently in either form.
"""

from __future__ import annotations

import copy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from collectors import nvd_collector, otx_collector  # noqa: E402
from collectors.nvd_collector import NVDCollector  # noqa: E402
from collectors.otx_collector import OTXCollector  # noqa: E402

# "" = the timestamp exactly as the source sends it (no zone); "Z" = the same instant, zoned.
_ZONE = pytest.mark.parametrize("zone", ["", "Z"], ids=["zone-less-as-sent", "zoned"])


# --------------------------------------------------------------------------- NVD
# CVE-2021-44228 as NVD CVE API 2.0 returned it on 2026-10-14, trimmed to the fields the collector
# reads (one of 20 configuration nodes, one of 103 references, first sentences of the texts).
_LOG4SHELL = {
    "cve": {
        "id": "CVE-2021-44228",
        "sourceIdentifier": "security@apache.org",
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2026-08-11T19:33:44.513",
        "vulnStatus": "Analyzed",
        "cisaExploitAdd": "2021-12-10",
        "cisaActionDue": "2021-12-24",
        "cisaRequiredAction": (
            "For all affected software assets for which updates exist, the only acceptable "
            "remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks."
        ),
        "cisaVulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "descriptions": [
            {
                "lang": "en",
                "value": (
                    "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, "
                    "and 2.3.1) JNDI features used in configuration, log messages, and parameters do not "
                    "protect against attacker controlled LDAP and other JNDI related endpoints."
                ),
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "scope": "CHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "HIGH",
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 6.0,
                }
            ]
        },
        "weaknesses": [
            {"source": "nvd@nist.gov", "type": "Secondary", "description": [{"lang": "en", "value": "CWE-917"}]}
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.13.0",
                                "versionEndExcluding": "2.15.0",
                                "matchCriteriaId": "D31D423D-FC4D-428A-B863-55AF472B80DC",
                            }
                        ],
                    }
                ]
            }
        ],
        "references": [
            {
                "url": "https://logging.apache.org/log4j/2.x/security.html",
                "source": "security@apache.org",
                "tags": ["Release Notes", "Vendor Advisory"],
            }
        ],
    }
}


def _nvd_record(published: str) -> dict:
    record = copy.deepcopy(_LOG4SHELL)
    record["cve"]["published"] = published
    return record


def _nvd_collector() -> NVDCollector:
    c = NVDCollector.__new__(NVDCollector)
    c.base_url = "http://nvd.invalid"
    c.api_key = "test-key"
    c._api_key_rejected = False
    c.tag = "nvd"
    c.misp_writer = MagicMock()
    c.source_name = "nvd"
    c.circuit_breaker = MagicMock()
    return c


class TestNvdKeepsOldCves:
    @_ZONE
    def test_incremental_run_keeps_an_old_cve_whose_record_changed(self, zone):
        # An incremental run asks NVD for the CVEs modified in its lastMod window; Log4Shell
        # (published 2021-12, last modified 2026-08) is in NVD's answer whenever NVD updates it.
        # Whether the newest-first selection reaches it is a separate question (at today's volumes
        # it does not, docs/COLLECTORS.md § 2); once a record is fetched, its age must not drop it.
        with (
            patch.object(NVDCollector, "check_service_available", return_value=True),
            patch.object(NVDCollector, "_fetch_cves", return_value=[_nvd_record("2021-12-10T10:15:09.143" + zone)]),
        ):
            items = _nvd_collector().collect(limit=10, push_to_misp=False, baseline=False)

        assert [i["cve_id"] for i in items] == ["CVE-2021-44228"]
        published_at = datetime.fromisoformat(items[0]["published"])
        assert published_at == datetime(2021, 12, 10, 10, 15, 9, 143000, tzinfo=timezone.utc), "zone-less = UTC"
        assert items[0]["cvss_score"] == 10.0
        assert items[0]["cisa_exploit_add"] == "2021-12-10"

    @_ZONE
    def test_baseline_longer_than_24_months_keeps_what_its_windows_returned(self, zone):
        # A 1,095-day baseline asks NVD for three years of publication windows. A CVE published
        # 900 days ago is in one of them; the former filter would have dropped it after the fetch.
        published = (datetime.now(timezone.utc) - timedelta(days=900)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        published_at = datetime.fromisoformat(published).replace(tzinfo=timezone.utc)
        record = _nvd_record(published + zone)

        def fake_batch(self, pub_start_iso=None, pub_end_iso=None, start_index=0, limit=2000, **_filters):
            if pub_start_iso is None:  # requests without a publication window: nothing here
                return []
            start = datetime.fromisoformat(pub_start_iso)
            end = datetime.fromisoformat(pub_end_iso)
            return [record] if start_index == 0 and start <= published_at <= end else []

        with (
            patch.object(NVDCollector, "check_service_available", return_value=True),
            patch.object(NVDCollector, "_fetch_cves_batch", fake_batch),
            patch.object(nvd_collector, "get_source_checkpoint", return_value={}),
            patch.object(nvd_collector, "update_source_checkpoint"),
            patch.object(nvd_collector.time, "sleep"),
        ):
            items = _nvd_collector().collect(push_to_misp=False, baseline=True, baseline_days=1095)

        assert [i["cve_id"] for i in items] == ["CVE-2021-44228"]
        assert datetime.fromisoformat(items[0]["published"]) == published_at


# --------------------------------------------------------------------------- OTX
# The OTX pulse "Microsoft Phishing Collection" (63d10e46581edfe9bba0da3f) as OTX returned it on
# 2026-10-14: created 2023-01-25, still updated (modified 2026-10-13). Two of its 93 indicators,
# the oldest and the newest, with their real types and timestamps; the IOC values are replaced by
# documentation-reserved ones.
_OLD_PULSE = {
    "id": "63d10e46581edfe9bba0da3f",
    "name": "Microsoft Phishing Collection",
    "description": "This page stores Microsoft phishing page IOCs.",
    "author_name": "noladefense",
    "created": "2023-01-25T11:11:02.458000",
    "modified": "2026-10-13T23:37:29.579000",
    "revision": 1,
    "public": 1,
    "TLP": "green",
    "adversary": "",
    "tags": ["urls", "phishing", "scam", "microsoft"],
    "references": [],
    "industries": [],
    "targeted_countries": [],
    "malware_families": [],
    "attack_ids": [],
    "indicators": [
        {
            "id": 3626149020,
            "indicator": "https://phish-2023.example.com/?sso_reload=true",
            "type": "URL",
            "created": "2023-02-03T14:31:56",
            "content": "",
            "title": "",
            "description": "",
            "expiration": None,
            "is_active": 1,
        },
        {
            "id": 4526831457,
            "indicator": "phish-2026.example.net",
            "type": "hostname",
            "created": "2026-10-13T23:37:31",
            "content": "",
            "title": "",
            "description": "",
            "expiration": None,
            "is_active": 1,
        },
    ],
}


def _otx_collector() -> OTXCollector:
    c = OTXCollector.__new__(OTXCollector)
    c.api_key = "a" * 64
    c.tag = "alienvault_otx"
    c.session = MagicMock()
    c.rate_limiter = MagicMock()
    c._last_http_status = 200
    c.circuit_breaker = MagicMock()
    c.misp_writer = None
    c.source_name = "otx"
    return c


class TestOtxKeepsOldPulsesThatAreStillUpdated:
    @_ZONE
    @pytest.mark.parametrize("baseline", [False, True], ids=["incremental", "baseline"])
    def test_every_ioc_of_the_pulse_is_kept(self, zone, baseline):
        pulse = copy.deepcopy(_OLD_PULSE)
        pulse["created"] += zone
        pages = iter([[pulse]])
        c = _otx_collector()
        with (
            patch.object(c, "check_service_available", return_value=True),
            patch.object(c, "_fetch_pulses", side_effect=lambda **_kw: next(pages, [])),
            patch.object(otx_collector.time, "sleep"),
            patch.object(otx_collector, "get_source_incremental", return_value={}),
            patch.object(otx_collector, "update_source_incremental"),
            # Page ceilings are read from the environment at import; fixed here so a developer's
            # EDGEGUARD_OTX_*_MAX_PAGES=0 cannot empty the run.
            patch.object(otx_collector, "OTX_BASELINE_MAX_PAGES", 200),
            patch.object(otx_collector, "OTX_INCREMENTAL_MAX_PAGES", 10),
        ):
            items = c.collect(limit=10, push_to_misp=False, baseline=baseline, baseline_days=730)

        iocs = {i["value"]: i for i in items if i.get("value")}
        assert set(iocs) == {"https://phish-2023.example.com/?sso_reload=true", "phish-2026.example.net"}
        assert iocs["phish-2026.example.net"]["first_seen"] == "2026-10-13T23:37:31", "the IOC added on 2026-10-13"
        assert iocs["phish-2026.example.net"]["pulse_id"] == "63d10e46581edfe9bba0da3f"
