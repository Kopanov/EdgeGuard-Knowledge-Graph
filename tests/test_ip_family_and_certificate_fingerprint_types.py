"""IPv6 indicators keep their address family; SSL Blacklist fingerprints are certificate fingerprints.

MISP has no IPv6 attribute type: MISPWriter sends IPv4 and IPv6 addresses as ``ip-dst``. The sync
mapped ``ip-dst`` / ``ip-src`` to ``ipv4``, so every IPv6 IOC (OTX, AbuseIPDB) became an
``Indicator {indicator_type: "ipv4"}`` and was exported as ``[ipv4-addr:value = '2001:…']``. The
address now decides (``ioc_normalize.ip_address_type``): in the sync, on the read side, in the STIX
exporter and in the sync's MISP → STIX conversion.

The SSL Blacklist lists SHA-1 fingerprints of TLS certificates. Typed ``sha1``, they became
file-hash Indicators exported as ``[file:hashes.'SHA-1' = …]``. They are now MISP
``x509-fingerprint-sha1`` attributes and ``x509-fingerprint-sha1`` Indicators, exported as
``[x509-certificate:hashes.'SHA-1' = …]``.

The OTX pulse has the layout OTX's API returns (as in ``test_otx_non_file_hashes``) and the CSV the
SSL Blacklist layout (as in ``test_feed_failure_policy``). Addresses come from the documentation
ranges (RFC 5737, RFC 3849).
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest
import stix2

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from collectors import collector_utils, otx_collector  # noqa: E402
from collectors import finance_feed_collector as finance  # noqa: E402
from collectors import misp_writer as mw  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from collectors.otx_collector import OTXCollector  # noqa: E402
from ioc_normalize import MISP_IP_ATTRIBUTE_TYPES, canonicalize_lookup, ip_address_type  # noqa: E402
from node_identity import canonicalize_merge_key  # noqa: E402
from resilience import CircuitBreaker  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402
from stix_exporter import StixExporter, _build_pattern  # noqa: E402

_IPV4 = "203.0.113.5"
_IPV6 = "2001:db8:85a3::8a2e:370:7334"
_FINGERPRINT = "0123456789abcdef0123456789abcdef01234567"
_ATTRIBUTE_UUID = "5f0c1a8e-1b2c-4d3e-8f90-123456789abc"
_SSLBL_CSV = f"# comment\r\nListingdate,SHA1,Listingreason\r\n2024-05-01 10:00:00,{_FINGERPRINT},Dridex C&C\r\n"


# ---------------------------------------------------------------------------
# Pipeline stages: collector → MISP → sync → graph merge key → STIX export
# ---------------------------------------------------------------------------


def _otx_indicator(n: int, ind_type: str, value: str) -> Dict[str, Any]:
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
    "name": "Loader infrastructure",
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
    "indicators": [_otx_indicator(1, "IPv4", _IPV4), _otx_indicator(2, "IPv6", _IPV6)],
}


def _collect_otx() -> List[Dict[str, Any]]:
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
        return [i for i in c.collect(limit=10, push_to_misp=False, baseline=False) if i.get("value")]


def _writer() -> MISPWriter:
    return MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)


def _push(writer: MISPWriter, push) -> List[Dict[str, Any]]:
    """The attributes ``push`` (a callable that pushes through ``writer``) sends to MISP."""
    with (
        patch.object(writer, "_get_or_create_event", return_value="42"),
        patch.object(writer, "_push_batch", side_effect=lambda _eid, attrs: (len(attrs), 0)) as batch,
        patch.object(mw, "MISP_PREFETCH_EXISTING_ATTRS", False),
    ):
        push()
    return [attr for call in batch.call_args_list for attr in call.args[1]]


def _stored(attribute: Dict[str, Any]) -> Dict[str, Any]:
    """The attribute as MISP returns it to the sync: the pushed fields plus MISP's own."""
    return {**attribute, "uuid": _ATTRIBUTE_UUID, "event_id": "42", "category": "Network activity"}


def _sync(attribute: Dict[str, Any]) -> Dict[str, Any]:
    event = {"id": "42", "info": "EdgeGuard-test-2026-10-15", "date": "2026-10-15", "Tag": []}
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(_stored(attribute), event)
    assert item is not None
    return item


class _Session:
    """Neo4j session stand-in: the export query returns the seed, the source aggregates nothing."""

    def __init__(self, seed: Dict[str, Any]):
        self._seed = seed

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def run(self, cypher: str, **_params: Any):
        if "SOURCED_FROM" in cypher:
            return iter([])
        return iter(
            [{"seed": self._seed, "malware": [], "vulns": [], "techniques": [], "sectors": [], "campaigns": []}]
        )


def _export(synced: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Merge key of the synced item, then the STIX bundle ``export_indicator`` builds for that node."""
    key = canonicalize_merge_key("Indicator", {"indicator_type": synced["indicator_type"], "value": synced["value"]})
    seed = {**key, "edgeguard_managed": True, "tlp": synced["tlp"], "zone": synced["zone"]}
    client = MagicMock()
    client.driver.session.return_value = _Session(seed)
    bundle = StixExporter(client).export_indicator(key["value"])
    return key, bundle


def _indicator_pattern(bundle: Dict[str, Any]) -> str:
    stix2.parse(bundle)  # strict: allow_custom=False, and the Indicator's pattern is validated
    (indicator,) = [o for o in bundle["objects"] if o["type"] == "indicator"]
    return indicator["pattern"]


# ---------------------------------------------------------------------------
# 1. IP addresses: the address decides the family
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "address, graph_type, pattern",
    [
        (_IPV6, "ipv6", f"[ipv6-addr:value = '{_IPV6}']"),
        # Unchanged: an IPv4 address is still an ipv4 Indicator and an ipv4-addr pattern.
        (_IPV4, "ipv4", f"[ipv4-addr:value = '{_IPV4}']"),
    ],
)
def test_otx_address_reaches_misp_as_ip_dst_and_keeps_its_family_in_graph_and_export(address, graph_type, pattern):
    (item,) = [i for i in _collect_otx() if i["value"] == address]
    writer = _writer()
    (pushed,) = _push(writer, lambda: writer.push_items([item]))
    assert pushed["type"] == "ip-dst"  # MISP's type for both families

    synced = _sync(pushed)
    assert synced["indicator_type"] == graph_type

    key, bundle = _export(synced)
    assert key == {"indicator_type": graph_type, "value": address}
    assert _indicator_pattern(bundle) == pattern


@pytest.mark.parametrize(
    "value, family",
    [
        (_IPV4, "ipv4"),
        (_IPV6, "ipv6"),
        ("2001:DB8::1", "ipv6"),
        ("203.0.113.0/24", "ipv4"),  # MISP's ip-src / ip-dst accept CIDR blocks
        ("2001:db8::/32", "ipv6"),
        ("203.0.113.5|8080", "ipv4"),  # ip-dst|port composite value: the address part decides
        ("2001:db8::1|443", "ipv6"),
        ("fe80::1%eth0", "ipv6"),
        (" 203.0.113.5 ", "ipv4"),
        ("dead:beef", None),
        ("00:1a:2b:3c:4d:5e", None),
        ("203.0.113.5.7", None),
        ("evil.example", None),
        ("", None),
        (None, None),
    ],
)
def test_address_family_of_a_misp_ip_value(value, family):
    assert ip_address_type(value) == family


_MISP_IP_VALUES = [_IPV4, _IPV6, "203.0.113.0/24", "2001:db8::/48", "not-an-address"]


@pytest.mark.parametrize("misp_type", sorted(MISP_IP_ATTRIBUTE_TYPES))
@pytest.mark.parametrize("value", _MISP_IP_VALUES)
def test_sync_and_read_side_resolve_ip_src_and_ip_dst_alike(misp_type, value):
    """The sync's type is the type of the node's merge key; the read side (REST search, STIX export,
    alert enrichment and the alert-path MERGE) must resolve the same MISP type and value to it.
    The sync also keys the Indicator end of the edges it builds with that type."""
    attribute = {"type": misp_type, "value": value, "Tag": [{"name": 'misp-galaxy:malware="Emotet"'}]}
    synced = _sync(attribute)
    expected = {_IPV4: "ipv4", _IPV6: "ipv6", "203.0.113.0/24": "ipv4", "2001:db8::/48": "ipv6"}.get(value, "ipv4")
    assert synced["indicator_type"] == expected
    assert [r["from_key"]["indicator_type"] for r in synced["relationships"]] == [expected]
    assert canonicalize_lookup(misp_type, value)[0] == expected


@pytest.mark.parametrize(
    "indicator_type, value, pattern",
    [
        # Graphs synced before the fix hold IPv6 addresses typed ipv4.
        ("ipv4", _IPV6, f"[ipv6-addr:value = '{_IPV6}']"),
        ("ip-dst", _IPV6, f"[ipv6-addr:value = '{_IPV6}']"),
        ("ip-dst|port", "2001:db8::1|443", "[ipv6-addr:value = '2001:db8::1']"),
        ("ip", "2001:db8::/32", "[ipv6-addr:value = '2001:db8::/32']"),
        ("ipv6", _IPV4, f"[ipv4-addr:value = '{_IPV4}']"),
        # A value that is not an address keeps the declared family.
        ("ipv6", "not-an-address", "[ipv6-addr:value = 'not-an-address']"),
        ("ipv4", "not-an-address", "[ipv4-addr:value = 'not-an-address']"),
    ],
)
def test_stix_pattern_takes_the_family_from_the_address(indicator_type, value, pattern):
    assert _build_pattern(indicator_type, value) == pattern
    stix2.Indicator(pattern=pattern, pattern_type="stix", valid_from="2026-01-01T00:00:00Z")


def test_misp_to_stix_conversion_takes_the_family_from_the_address():
    """``MISPToNeo4jSync.convert_to_stix21`` (``run_pipeline.py`` STIX export and ``--stix-flow``)
    falls back to ``_attribute_to_stix21``: PyMISP has no ``to_stix2``."""
    sync = MISPToNeo4jSync(neo4j_client=MagicMock())
    sco = sync._attribute_to_stix21({"type": "ip-dst", "value": _IPV6, "uuid": _ATTRIBUTE_UUID}, "event-uuid")
    assert (sco["type"], sco["id"], sco["value"]) == ("ipv6-addr", f"ipv6-addr--{_ATTRIBUTE_UUID}", _IPV6)
    stix2.parse(sco)
    sco = sync._attribute_to_stix21({"type": "ip-src", "value": _IPV4, "uuid": _ATTRIBUTE_UUID}, "event-uuid")
    assert (sco["type"], sco["value"]) == ("ipv4-addr", _IPV4)
    assert sync._value_to_stix_pattern("ip-src", _IPV6) == f"[ipv6-addr:value = '{_IPV6}']"
    assert sync._value_to_stix_pattern("ip-dst", _IPV4) == f"[ipv4-addr:value = '{_IPV4}']"


def test_keyword_query_for_ip_addresses_covers_both_families():
    import query_api

    cypher = query_api._parse_natural_language("show malicious ip addresses")
    assert "n.indicator_type IN ['ipv4', 'ipv6']" in cypher


# ---------------------------------------------------------------------------
# 2. SSL Blacklist: TLS certificate fingerprints
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, text: str):
        self.status_code = 200
        self.text = text
        self.headers: Dict[str, str] = {}

    def raise_for_status(self) -> None:
        return None


def test_sslbl_fingerprint_reaches_misp_syncs_and_exports_as_a_certificate_fingerprint(monkeypatch):
    monkeypatch.setattr(finance, "request_with_rate_limit_retries", lambda *_a, **_kw: _Resp(_SSLBL_CSV))
    monkeypatch.setattr(collector_utils.time, "sleep", lambda _s: None)
    monkeypatch.setattr(finance, "SSLBL_CIRCUIT_BREAKER", CircuitBreaker("sslbl_types_test", failure_threshold=3))
    monkeypatch.setattr(finance.SSLBL_RATE_LIMITER, "wait_if_needed", lambda: None)
    writer = _writer()
    collector = finance.SSLBlacklistCollector(misp_writer=writer)
    status: Dict[str, Any] = {}
    (pushed,) = _push(writer, lambda: status.update(collector.collect(push_to_misp=True)))
    assert status["success"] is True and status["count"] == 1
    assert (pushed["type"], pushed["value"]) == ("x509-fingerprint-sha1", _FINGERPRINT)

    synced = _sync(pushed)
    assert (synced["indicator_type"], synced["tag"]) == ("x509-fingerprint-sha1", "ssl_blacklist")

    key, bundle = _export(synced)
    assert key == {"indicator_type": "x509-fingerprint-sha1", "value": _FINGERPRINT}
    assert _indicator_pattern(bundle) == f"[x509-certificate:hashes.'SHA-1' = '{_FINGERPRINT}']"


def test_misp_knows_the_certificate_fingerprint_type_and_every_indicator_type_the_writer_maps_to():
    """Checked against the MISP type list PyMISP ships (``pymisp/data/describeTypes.json``):
    the new type and every MISP type in ``MISPWriter.TYPE_MAPPING``. MISPWriter sends no
    category, so MISP files the attribute under the type's default category."""
    try:
        dist = importlib.metadata.distribution("pymisp")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("pymisp is not installed")
    describe = json.loads(Path(str(dist.locate_file("pymisp/data/describeTypes.json"))).read_text("utf-8"))["result"]
    assert MISPWriter.TYPE_MAPPING["x509-fingerprint-sha1"] == "x509-fingerprint-sha1"
    assert set(MISPWriter.TYPE_MAPPING.values()) <= set(describe["types"])
    default_category = describe["sane_defaults"]["x509-fingerprint-sha1"]["default_category"]
    assert "x509-fingerprint-sha1" in describe["category_type_mappings"][default_category]


@pytest.mark.parametrize(
    "value, pattern",
    [
        (_FINGERPRINT, f"[x509-certificate:hashes.'SHA-1' = '{_FINGERPRINT}']"),
        (_FINGERPRINT.upper(), f"[x509-certificate:hashes.'SHA-1' = '{_FINGERPRINT.upper()}']"),
        # Not a SHA-1 digest: the custom key keeps the pattern valid without claiming an algorithm.
        ("DA:39:A3", "[x509-certificate:hashes.'UNKNOWN' = 'DA:39:A3']"),
    ],
)
def test_certificate_fingerprint_pattern_is_on_x509_certificate(value, pattern):
    assert _build_pattern("x509-fingerprint-sha1", value) == pattern
    stix2.Indicator(pattern=pattern, pattern_type="stix", valid_from="2026-01-01T00:00:00Z")


def test_misp_to_stix_conversion_of_a_certificate_fingerprint():
    sync = MISPToNeo4jSync(neo4j_client=MagicMock())
    attribute = {"type": "x509-fingerprint-sha1", "value": _FINGERPRINT, "uuid": _ATTRIBUTE_UUID}
    sco = sync._attribute_to_stix21(attribute, "event-uuid")
    assert sco == {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": f"x509-certificate--{_ATTRIBUTE_UUID}",
        "hashes": {"SHA-1": _FINGERPRINT},
    }
    stix2.parse(sco)


def test_certificate_fingerprint_merge_key_folds_case():
    """A hex digest: the merge key is lower-case whatever case a source sends."""
    key = canonicalize_merge_key(
        "Indicator", {"indicator_type": "x509-fingerprint-sha1", "value": f" {_FINGERPRINT.upper()} "}
    )
    assert key["value"] == _FINGERPRINT


def test_rest_indicator_filter_accepts_the_certificate_fingerprint_type(monkeypatch):
    """``IndicatorTypeEnum`` validates ``indicator_type`` on ``/indicators`` and the Wazuh CDB export."""
    from fastapi.testclient import TestClient

    import query_api

    session = MagicMock()
    session.__enter__.return_value = session
    count = MagicMock()
    count.single.return_value = {"total": 0}
    session.run.side_effect = [iter([]), count]
    client = MagicMock()
    client.is_connected.return_value = True
    client.driver.session.return_value = session
    monkeypatch.setattr(query_api, "neo4j_client", client)

    response = TestClient(query_api.app).get("/indicators", params={"indicator_type": "x509-fingerprint-sha1"})
    assert response.status_code == 200, response.text
    assert session.run.call_args_list[0].kwargs["indicator_type"] == "x509-fingerprint-sha1"
