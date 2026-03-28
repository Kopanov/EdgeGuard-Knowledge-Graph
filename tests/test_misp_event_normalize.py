"""MISP event list normalization (wrapped {'Event': ...} vs flat dicts)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from run_misp_to_neo4j import (  # noqa: E402
    MISPToNeo4jSync,
    _unwrap_single_misp_event_row,
    apply_edgeguard_zone_metadata_to_stix_dict,
    coerce_misp_attribute_list,
    misp_event_object_to_event_dict,
    normalize_misp_event_index_payload,
    normalize_misp_tag_list,
)


def test_unwrap_nested_event():
    row = {"Event": {"id": "42", "info": "EdgeGuard-test", "Attribute": []}}
    assert _unwrap_single_misp_event_row(row) == row["Event"]


def test_unwrap_already_flat():
    flat = {"id": "7", "info": "EdgeGuard-x"}
    assert _unwrap_single_misp_event_row(flat) is flat


def test_normalize_list_of_wrapped():
    raw = [
        {"Event": {"id": "1", "info": "a"}},
        {"Event": {"id": "2", "info": "b"}},
    ]
    out = normalize_misp_event_index_payload(raw)
    assert len(out) == 2
    assert out[0]["id"] == "1"
    assert out[1]["info"] == "b"


def test_normalize_response_wrapper():
    raw = {"response": [{"Event": {"id": "99", "info": "EdgeGuard"}}]}
    out = normalize_misp_event_index_payload(raw)
    assert len(out) == 1
    assert out[0]["id"] == "99"


def test_normalize_events_key_wrapper():
    raw = {"events": [{"Event": {"id": "3", "info": "x"}}]}
    out = normalize_misp_event_index_payload(raw)
    assert len(out) == 1
    assert out[0]["id"] == "3"


def test_normalize_single_wrapped_dict():
    raw = {"Event": {"id": "5", "info": "solo"}}
    out = normalize_misp_event_index_payload(raw)
    assert len(out) == 1
    assert out[0]["id"] == "5"


def test_empty_and_none():
    assert normalize_misp_event_index_payload(None) == []
    assert normalize_misp_event_index_payload([]) == []


def test_misp_event_object_to_event_dict_wrapped_and_flat():
    assert misp_event_object_to_event_dict({"Event": {"id": "1", "info": "x"}})["id"] == "1"
    assert misp_event_object_to_event_dict({"id": "2", "Attribute": []})["id"] == "2"


def test_coerce_misp_attribute_list():
    assert coerce_misp_attribute_list(None) == []
    assert len(coerce_misp_attribute_list({"type": "ip-dst", "value": "1.1.1.1"})) == 1
    assert len(coerce_misp_attribute_list([{"type": "x", "value": "y"}])) == 1


def test_normalize_misp_tag_list_strings_and_singleton():
    assert normalize_misp_tag_list("source:otx") == [{"name": "source:otx"}]
    assert normalize_misp_tag_list({"name": "zone:finance"}) == [{"name": "zone:finance"}]
    assert normalize_misp_tag_list(["source:nvd", {"name": "sector:energy"}])[0]["name"] == "source:nvd"


def test_stix21_sco_uses_x_edgeguard_zones_not_labels():
    """STIX 2.1 SCOs must not carry ``labels``; EdgeGuard uses x_edgeguard_zones (see spec)."""
    o = {"type": "ipv4-addr", "spec_version": "2.1", "id": "ipv4-addr--test", "value": "1.1.1.1"}
    apply_edgeguard_zone_metadata_to_stix_dict(o, ["zone:finance"])
    assert "labels" not in o
    assert o.get("x_edgeguard_zones") == ["zone:finance"]


def test_stix21_sdo_gets_labels():
    o = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--test",
        "pattern": "[ipv4-addr:value = '1.1.1.1']",
    }
    apply_edgeguard_zone_metadata_to_stix_dict(o, ["zone:energy"])
    assert o.get("labels") == ["zone:energy"]


def test_stix21_sco_migrates_zone_like_labels_from_pymisp():
    o = {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": "domain-name--t",
        "value": "x.com",
        "labels": ["zone:healthcare"],
    }
    apply_edgeguard_zone_metadata_to_stix_dict(o, [])
    assert "labels" not in o
    assert "zone:healthcare" in o.get("x_edgeguard_zones", [])


def test_attribute_to_stix21_strips_redundant_global_when_specific_present():
    """Align STIX zone list with parse_attribute (specifics win over global)."""
    sync = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    attr = {
        "type": "ip-dst",
        "value": "10.0.0.1",
        "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "Tag": [{"name": "zone:global"}, {"name": "zone:energy"}],
    }
    stix = MISPToNeo4jSync._attribute_to_stix21(sync, attr, "event-uuid", ["global"])
    assert stix.get("x_edgeguard_zones") == ["zone:energy"]


def test_attribute_to_stix21_event_zones_global_plus_specific_normalized():
    sync = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    attr = {
        "type": "ip-dst",
        "value": "10.0.0.2",
        "uuid": "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee",
        "Tag": [],
    }
    stix = MISPToNeo4jSync._attribute_to_stix21(sync, attr, "event-uuid", ["global", "finance"])
    assert stix.get("x_edgeguard_zones") == ["zone:finance"]
