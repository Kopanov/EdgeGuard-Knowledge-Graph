"""Optional API keys: collectors return success + skipped for Airflow (see run_collector_with_metrics)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def test_vt_collector_skips_when_no_key_push_to_misp():
    from collectors.vt_collector import VTCollector

    vt = VTCollector(misp_writer=MagicMock())
    vt.api_key = None
    out = vt.collect(limit=5, push_to_misp=True, baseline=False)
    assert isinstance(out, dict)
    assert out["success"] is True
    assert out.get("skipped") is True
    assert out.get("skip_reason_class") == "missing_virustotal_key"
    assert out["source"] == "virustotal"


def test_vt_collector_placeholder_key_skips_push_to_misp():
    from collectors.vt_collector import VTCollector

    vt = VTCollector(misp_writer=MagicMock())
    vt.api_key = "YOUR_VT_API_KEY"
    out = vt.collect(limit=5, push_to_misp=True)
    assert out["success"] is True and out.get("skipped") is True


def test_virustotal_enrich_collector_skips_when_no_key_push_to_misp():
    from collectors.virustotal_collector import VirusTotalCollector

    c = VirusTotalCollector(misp_writer=MagicMock())
    c.api_key = None
    out = c.collect(limit=5, push_to_misp=True)
    assert out["success"] is True
    assert out.get("skipped") is True
    assert out.get("skip_reason_class") == "missing_virustotal_key"
    assert out["source"] == "virustotal_enrich"


@pytest.mark.parametrize("key_val", ["", None, "YOUR_OTX_API_KEY_HERE"])
def test_otx_collector_skips_when_no_key_push_to_misp(key_val: str | None):
    from collectors.otx_collector import OTXCollector

    c = OTXCollector(misp_writer=MagicMock())
    c.api_key = key_val
    out = c.collect(limit=10, push_to_misp=True, baseline=False)
    assert isinstance(out, dict)
    assert out["success"] is True
    assert out.get("skipped") is True
    assert out.get("skip_reason_class") == "missing_otx_key"
    assert out["source"] == "otx"
    assert "circuit_breaker_state" in out


def test_otx_collector_no_key_returns_empty_list_when_not_push():
    from collectors.otx_collector import OTXCollector

    c = OTXCollector(misp_writer=MagicMock())
    c.api_key = ""
    assert c.collect(limit=10, push_to_misp=False, baseline=False) == []
