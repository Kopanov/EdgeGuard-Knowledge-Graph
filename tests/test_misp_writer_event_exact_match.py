"""MISPWriter event lookup: exact Event.info match (restSearch substring pitfall)."""

from collectors import misp_writer as mw


def test_exact_info_rejects_wrong_substring_match():
    mitre = "EdgeGuard-GLOBAL-mitre_attck-2026-03-24"
    cisa = "EdgeGuard-GLOBAL-cisa_kev-2026-03-24"
    rows = [{"Event": {"id": "11", "info": mitre}}]
    assert mw._event_id_exact_from_restsearch_rows(rows, cisa) is None
    assert mw._event_id_exact_from_restsearch_rows(rows, mitre) == "11"


def test_exact_info_picks_correct_row_when_multiple_returned():
    rows = [
        {"Event": {"id": "11", "info": "EdgeGuard-GLOBAL-mitre_attck-2026-03-24"}},
        {"Event": {"id": "22", "info": "EdgeGuard-GLOBAL-cisa_kev-2026-03-24"}},
    ]
    assert mw._event_id_exact_from_restsearch_rows(rows, "EdgeGuard-GLOBAL-cisa_kev-2026-03-24") == "22"


def test_exact_info_flat_row_shape():
    rows = [{"id": "7", "info": "EdgeGuard-GLOBAL-nvd-2026-03-24"}]
    assert mw._event_id_exact_from_restsearch_rows(rows, "EdgeGuard-GLOBAL-nvd-2026-03-24") == "7"


def test_primary_sector_for_event_grouping_matches_zone_tag_logic():
    """push_items must not use zones[0] when global is mixed with specifics."""
    w = mw.MISPWriter.__new__(mw.MISPWriter)
    assert w._primary_sector_for_event_grouping({"zone": ["global", "energy"]}) == "energy"
    assert w._primary_sector_for_event_grouping({"zone": ["energy", "global"]}) == "energy"
    assert w._primary_sector_for_event_grouping({"zone": ["finance", "healthcare"]}) == "finance"
    assert w._primary_sector_for_event_grouping({"zone": ["global"]}) == "global"
