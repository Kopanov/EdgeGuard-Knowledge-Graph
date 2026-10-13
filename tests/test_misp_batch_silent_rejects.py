"""Attributes MISP silently drops from a batch push (HTTP 200, attribute not stored).

Found on a 730-day fresh baseline by pushing each absent OTX attribute alone and reading
MISP's validation answer:

1. ``Last seen value should be greater than first seen value``: OTX indicators whose
   ``modified`` precedes ``created`` by a second or two. ``_apply_source_truthful_timestamps``
   already drops such a ``last_seen`` on main; the first two tests pin it for OTX's sub-second shape.
2. ``Domain has an invalid format``: e-mail addresses that the OTX fallback typed as ``domain``.
"""

from collectors import misp_writer as mw
from collectors.otx_collector import OTXCollector


def _stamp(item):
    attribute = {}
    mw._apply_source_truthful_timestamps(attribute, item)
    return attribute


def test_last_seen_before_first_seen_is_dropped():
    attr = _stamp({"first_seen": "2026-09-30T18:56:04+00:00", "last_seen": "2026-09-30T18:56:02.517000+00:00"})
    assert attr.get("first_seen")
    assert "last_seen" not in attr


def test_consistent_or_equal_timestamps_are_kept():
    attr = _stamp({"first_seen": "2026-09-30T18:56:02+00:00", "last_seen": "2026-09-30T18:56:04+00:00"})
    assert attr.get("first_seen") and attr.get("last_seen")
    same = _stamp({"first_seen": "2026-09-30T18:56:02+00:00", "last_seen": "2026-09-30T18:56:02+00:00"})
    assert same.get("first_seen") and same.get("last_seen")


def test_otx_email_values_are_not_typed_as_domains():
    c = OTXCollector.__new__(OTXCollector)
    assert c.map_indicator_type("email", "8139@shengan-light.com.tw") == "email"
    assert c.map_indicator_type("unknown-type", "8139@shengan-light.com.tw") == "email"
    assert c.map_indicator_type("unknown-type", "shengan-light.com.tw") == "domain"
