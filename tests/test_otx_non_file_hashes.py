"""OTX indicators whose value is a hex digest of something other than a file are not collected.

MISPWriter types a generic ``hash`` by its digest length (2026-10): OTX's FileHash-MD5 / -SHA1 /
-SHA256 indicators then reach MISP as md5 / sha1 / sha256 instead of all being sent as sha256 and
dropped. An import hash (FileHash-IMPHASH, 32 hex characters), a PE hash (FileHash-PEHASH, 40), a
JA3 TLS fingerprint (32) and an SSL certificate fingerprint (40) would take the same path and be
stored as file hashes, so the collector leaves them out. The pulse has the layout OTX's API
returns; the type names are OTX's, the values are well-known test digests.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from collectors import otx_collector  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from collectors.otx_collector import OTXCollector  # noqa: E402

_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def _indicator(n: int, ind_type: str, value: str) -> dict:
    return {
        "id": 4526831400 + n,
        "indicator": value,
        "type": ind_type,
        "created": "2026-10-13T23:37:31",
        "content": "",
        "title": "",
        "description": "",
        "expiration": None,
        "is_active": 1,
    }


_PULSE = {
    "id": "6710e46581edfe9bba0da3f1",
    "name": "Loader campaign",
    "description": "",
    "author_name": "example",
    "created": "2026-10-13T11:11:02.458000",
    "modified": "2026-10-13T23:37:29.579000",
    "revision": 1,
    "public": 1,
    "TLP": "white",
    "adversary": "",
    "tags": [],
    "references": [],
    "industries": [],
    "targeted_countries": [],
    "malware_families": [],
    "attack_ids": [],
    "indicators": [
        _indicator(1, "FileHash-MD5", _MD5),
        _indicator(2, "FileHash-SHA1", _SHA1),
        _indicator(3, "FileHash-IMPHASH", "f34d5f2d4577ed6d9ceec516c1f5a744"),
        _indicator(4, "FileHash-PEHASH", "ffb7a38174aab4744cc4a509e34800aee9be8e57"),
        _indicator(5, "JA3", "e7d705a3286e19ea42f587b344ee6865"),
        _indicator(6, "SSLCertFingerprint", "a9f3c2b1d4e5f60718293a4b5c6d7e8f90a1b2c3"),
    ],
}


def _collect() -> list:
    c = OTXCollector.__new__(OTXCollector)
    c.api_key = "a" * 64
    c.tag = "alienvault_otx"
    c.session = MagicMock()
    c.rate_limiter = MagicMock()
    c._last_http_status = 200
    c.circuit_breaker = MagicMock()
    c.misp_writer = None
    c.source_name = "otx"
    pages = iter([[_PULSE]])
    with (
        patch.object(c, "check_service_available", return_value=True),
        patch.object(c, "_fetch_pulses", side_effect=lambda **_kw: next(pages, [])),
        patch.object(otx_collector.time, "sleep"),
        patch.object(otx_collector, "get_source_incremental", return_value={}),
        patch.object(otx_collector, "update_source_incremental"),
        patch.object(otx_collector, "OTX_INCREMENTAL_MAX_PAGES", 10),
    ):
        return c.collect(limit=10, push_to_misp=False, baseline=False)


def test_only_the_file_hashes_are_collected_and_typed_by_length():
    items = [i for i in _collect() if i.get("value")]
    assert sorted(i["value"] for i in items) == sorted([_MD5, _SHA1])
    writer = MISPWriter.__new__(MISPWriter)
    types = {i["value"]: writer.map_indicator_type(i["indicator_type"], i["value"]) for i in items}
    assert types == {_MD5: "md5", _SHA1: "sha1"}


def test_the_skip_is_counted_in_the_log(caplog):
    with caplog.at_level("INFO", logger=otx_collector.logger.name):
        _collect()
    assert any("[SKIP] OTX: 4 indicators of a non-file hash type" in r.getMessage() for r in caplog.records)
