"""NVD sector detection: CPE flattening + detect_zones_from_item integration."""

from __future__ import annotations

import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from collectors.nvd_collector import NVDCollector, configurations_to_zone_text  # noqa: E402
from config import detect_zones_from_text  # noqa: E402


def test_configurations_to_zone_text_extracts_vendor_product():
    cfg = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "criteria": "cpe:2.3:a:siemens:simatic_plc:1.0:*:*:*:*:*:*:*",
                            "vulnerable": True,
                        }
                    ]
                }
            ]
        }
    ]
    t = configurations_to_zone_text(cfg).lower()
    assert "siemens" in t
    assert "simatic" in t or "plc" in t


def test_detect_zones_single_hospital_sentence():
    text = "A vulnerability in hospital software allows remote code execution"
    assert detect_zones_from_text(text) == ["healthcare"]


def test_nvd_detect_sectors_description_only():
    from unittest.mock import MagicMock

    c = NVDCollector(misp_writer=MagicMock())
    zones = c.detect_sectors("Patient monitoring system allows privilege escalation", None)
    assert "healthcare" in zones


def test_nvd_detect_sectors_from_cpe_when_description_empty():
    from unittest.mock import MagicMock

    c = NVDCollector(misp_writer=MagicMock())
    cfg = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "criteria": "cpe:2.3:a:acme:scada_gateway:2:*:*:*:*:*:*:*",
                            "vulnerable": True,
                        }
                    ]
                }
            ]
        }
    ]
    zones = c.detect_sectors("", cfg)
    assert "energy" in zones
