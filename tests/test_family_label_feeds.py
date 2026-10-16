"""Q9 credits only the feeds that state an indicator's ``malware_family`` (2026-10).

Q9 (``build_relationships``, ``Indicator → Malware`` by family) names in ``r.sources`` the indicator's
feeds listed in ``relationship_provenance.FAMILY_LABEL_FEEDS`` and copies their record ids and MISP
events. The list named OTX, but the OTX collector puts no ``malware_family`` on an indicator: the
families a pulse names travel as ``pulse_malware_families`` (``OTX_META.mf``) and
``OTX_META.malware_family`` is always empty. So a family-labelled IOC that an OTX pulse also listed
got OTX in ``r.sources``, with every OTX pulse and MISP event of the indicator, on a link no OTX
record stated; the lists only grow, so no later run removed them. Step 9b links the families an OTX
pulse names, with OTX's provenance. These tests run the real collector, MISP writer and parser.
"""

from __future__ import annotations

import ast
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from build_rel_queries import assigned_query  # noqa: E402

import relationship_provenance as rp  # noqa: E402
from collectors import otx_collector as oc  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

_EVENT = {"id": 7, "info": "EdgeGuard-alienvault_otx-2026-10-16", "date": "2026-10-16", "Tag": []}


def _otx_items(pulse: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The OTX collector's items for one pulse (no HTTP, no MISP push)."""
    c = oc.OTXCollector.__new__(oc.OTXCollector)
    c.api_key = "test-otx-key-64chars" + "a" * 44
    c.tag = "alienvault_otx"
    c.session = MagicMock()
    c.rate_limiter = MagicMock()
    c._last_http_status = 200
    c.circuit_breaker = MagicMock()
    c.circuit_breaker.can_execute.return_value = True
    c.misp_writer = None
    c.source_name = "otx"
    c.health_check = MagicMock(return_value=True)
    pages = iter([[pulse]])
    with (
        patch.object(c, "check_service_available", return_value=True),
        patch.object(c, "_fetch_pulses", side_effect=lambda **kw: next(pages, [])),
        patch("collectors.otx_collector.time.sleep", lambda *_a, **_k: None),
        patch("collectors.otx_collector.get_source_incremental", return_value={}),
        patch("collectors.otx_collector.update_source_incremental", lambda *_a, **_k: None),
    ):
        return c.collect(limit=10, push_to_misp=False)


def _pulse_naming(family: str, ioc: str) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": "p-family",
        "name": f"{family} infrastructure",
        "created": now,
        "modified": now,
        "TLP": "green",
        "malware_families": [family],
        "indicators": [{"type": "IPv4", "indicator": ioc, "description": "C2"}],
    }


def test_an_otx_indicator_reaches_the_sync_without_a_malware_family():
    items = _otx_items(_pulse_naming("Emotet", "198.51.100.7"))
    ioc = next(i for i in items if i.get("value") == "198.51.100.7")
    assert not ioc.get("malware_family"), "the collector names the pulse's families on the indicator's list only"

    attr = MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False).create_attribute(ioc)
    assert attr["comment"].startswith("OTX_META:")
    assert json.loads(attr["comment"][len("OTX_META:") :])["malware_family"] == ""

    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(
        {**attr, "uuid": "20000000-0000-0000-0000-00000000f001"}, _EVENT
    )
    assert not item.get("malware_family"), "an OTX record never sets Indicator.malware_family (what Q9 matches)"
    assert item["pulse_malware_families"] == ["Emotet"], "the pulse's family is step 9b's to link"

    # So Q9 must not name OTX among the feeds that state the family.
    assert "alienvault_otx" not in ast.literal_eval(rp.FAMILY_LABEL_FEEDS)


def test_q9_reads_the_family_label_feeds_and_9b_credits_otx():
    q9 = assigned_query("_q9_inner")
    assert f"WHERE s IN {rp.FAMILY_LABEL_FEEDS}" in q9 and "alienvault_otx" not in q9
    q9b = assigned_query("_q9b_inner")
    assert f"{rp.OTX_FEEDS} AS _feeds" in q9b and "i.pulse_malware_families" in q9b
