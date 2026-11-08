"""ATT&CK objects of the same name, and the ATT&CK ids of groups and malware (2026-11).

A 7-day baseline with ATT&CK for ICS on (2026-11-01) showed two defects in the MITRE path:

1. ATT&CK publishes software of one name in two objects: the deprecated Enterprise ``TRITON``
   (S0609) beside the active ICS ``Triton`` (S1009), and the active ``KillDisk`` (S0607) beside a
   deprecated ICS copy ``Killdisk`` without an ATT&CK id. The collector pushed all four; MISP did not
   store ``Triton`` (the event already held ``TRITON``), the push confirmation compared values
   case-insensitively and reported no loss, the ``triton`` node carried the deprecated text with no
   technique links, and the ``killdisk`` node was marked deprecated by the copy, a flag no record
   could clear.
2. ``ThreatActor`` and ``Malware`` nodes carried no ATT&CK id, on the node or in ``source_refs``.

The collector now emits one item per node key, an active object winning over a deprecated one; the
push confirmation compares the types MISP stores verbatim exactly; an ATT&CK record sets
``n.deprecated`` either way; and groups and malware carry their ATT&CK id from the collector through
MISP (``aid`` in the ``MITRE_USES_TECHNIQUES`` block) to ``n.mitre_id`` and ``mitre_attck:<id>``.

Fixtures: ``tests/fixtures/attack_same_name_objects_2026_11_01.json`` (real objects of the ATT&CK
bundles) and ``tests/fixtures/misp_attack_case_variants_2026_11_01.json`` (the attributes MISP stored).
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from collectors import misp_writer as mw  # noqa: E402
from collectors import mitre_collector as mc  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_BUNDLES = json.loads((FIXTURES / "attack_same_name_objects_2026_11_01.json").read_text(encoding="utf-8"))
_MISP_STORED = json.loads((FIXTURES / "misp_attack_case_variants_2026_11_01.json").read_text(encoding="utf-8"))[
    "attributes"
]
ENT_URL = "https://ent.example/enterprise-attack.json"
ICS_URL = "https://ics.example/ics-attack.json"
EVENT = {"id": "40", "info": "EdgeGuard-mitre_attck-2026-11-01", "Tag": []}


def _bundle(domain: str) -> dict:
    return {"type": "bundle", "id": f"bundle--{domain}", "objects": deepcopy(_BUNDLES[domain])}


def _collector(monkeypatch, *, ics: bool = True, ics_fails: bool = False, etag=None):
    writer = MagicMock()
    writer.push_items.return_value = (1, 0)
    collector = mc.MITRECollector(misp_writer=writer)
    collector.attack_url = ENT_URL
    collector.ics_attack_url = ICS_URL
    breaker = MagicMock()
    breaker.can_execute.return_value = True
    monkeypatch.setattr(mc, "MITRE_CIRCUIT_BREAKER", breaker)
    monkeypatch.setattr(mc, "MITRE_MAX_RELATIONSHIPS", 0)
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", ics)
    collector.stored_etags = []
    monkeypatch.setattr(
        mc, "update_source_incremental", lambda _source, **k: collector.stored_etags.append(k.get("mitre_bundle_etag"))
    )
    monkeypatch.setattr(mc, "get_source_incremental", lambda *a, **k: {})
    monkeypatch.setattr(mc.MITRE_RATE_LIMITER, "wait_if_needed", lambda: None)
    monkeypatch.setattr(mc, "_record_ics_failure", lambda exc: None)

    def download(etag=None, url=None):
        if url == ICS_URL:
            if ics_fails:
                raise ConnectionError("ICS bundle unreachable")
            return _bundle("ics"), None
        return _bundle("enterprise"), etag_value

    etag_value = etag
    monkeypatch.setattr(collector, "_download_stix_bundle", download)
    return collector, writer


def _pushed_items(monkeypatch, *, ics: bool = True) -> list:
    """The items ``collect()`` hands to ``MISPWriter.push_items`` (the production path)."""
    collector, writer = _collector(monkeypatch, ics=ics)
    status = collector.collect(push_to_misp=True, baseline=True)
    assert status["success"] is True
    (items,), _ = writer.push_items.call_args
    return items


def _of(items: list, item_type: str) -> list:
    return [it for it in items if it.get("type") == item_type]


def _by_key(items: list) -> dict:
    """Items by lower-cased name; fails if two items share one (the Malware / ThreatActor node key)."""
    out: dict = {}
    for it in items:
        key = it["name"].strip().lower()
        assert key not in out, f"two items for one node key: {out[key]['name']!r} and {it['name']!r}"
        out[key] = it
    return out


def _writer() -> mw.MISPWriter:
    return mw.MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)


def _syncer():
    import run_misp_to_neo4j as sync_mod

    syncer = sync_mod.MISPToNeo4jSync.__new__(sync_mod.MISPToNeo4jSync)
    syncer.neo4j = MagicMock()
    syncer.stats = defaultdict(int)
    return syncer


def _as_stored(attribute: dict, n: int) -> dict:
    """``attribute`` as MISP lists it: a UUID and tag objects (MISPWriter builds ``{"name": ...}``)."""
    return {**attribute, "uuid": f"00000000-0000-4000-8000-{n:012d}", "Tag": list(attribute["Tag"])}


# --------------------------------------------------------------------------- 1. one item per node key
class TestOneItemPerNodeKey:
    def test_the_active_ics_triton_replaces_the_deprecated_enterprise_triton(self, monkeypatch):
        malware = _by_key(_of(_pushed_items(monkeypatch), "malware"))
        triton = malware["triton"]
        assert (triton["name"], triton["mitre_id"], triton["attack_domain"]) == ("Triton", "S1009", "ics")
        assert triton["deprecated"] is False
        assert triton["uses_techniques"] == ["T0880"]
        assert triton["description"].startswith("[Triton](https://attack.mitre.org/software/S1009)")

    def test_the_deprecated_ics_copy_does_not_reach_the_active_killdisk(self, monkeypatch):
        malware = _by_key(_of(_pushed_items(monkeypatch), "malware"))
        killdisk = malware["killdisk"]
        assert (killdisk["name"], killdisk["mitre_id"], killdisk["attack_domain"]) == (
            "KillDisk",
            "S0607",
            "enterprise",
        )
        assert killdisk["deprecated"] is False
        # The same STIX object in both bundles: Enterprise kept, the ICS technique link united.
        assert killdisk["uses_techniques"] == ["T1485", "T0809"]
        assert killdisk["description"].startswith("[KillDisk](https://attack.mitre.org/software/S0607)")

    def test_no_two_pushed_items_share_a_node_key(self, monkeypatch):
        items = _pushed_items(monkeypatch)
        for item_type in ("malware", "actor"):
            _by_key(_of(items, item_type))
        assert {it["name"] for it in _of(items, "malware")} == {"Triton", "KillDisk"}

    def test_without_ics_a_deprecated_object_is_kept_and_marked(self, monkeypatch):
        """Only an active object of the same name leaves a deprecated one out."""
        malware = _by_key(_of(_pushed_items(monkeypatch, ics=False), "malware"))
        assert (malware["triton"]["name"], malware["triton"]["mitre_id"]) == ("TRITON", "S0609")
        assert malware["triton"]["deprecated"] is True
        assert malware["killdisk"]["deprecated"] is False

    def test_a_group_of_deprecated_objects_keeps_its_first(self, monkeypatch):
        objects = _bundle("ics")["objects"]
        for obj in objects:
            if obj.get("type") == "malware" and obj["name"].lower() == "killdisk":
                obj["x_mitre_deprecated"] = True
        collector, _ = _collector(monkeypatch)
        parsed = collector._parse_bundle(objects, domain="ics", kill_chain_name=mc.ICS_KILL_CHAIN_NAME)
        killdisk = _by_key(parsed["malware"])["killdisk"]
        assert (killdisk["name"], killdisk["mitre_id"], killdisk["deprecated"]) == ("KillDisk", "S0607", True)

    def test_the_left_out_objects_are_logged(self, monkeypatch, caplog):
        with caplog.at_level(logging.INFO, logger=mc.logger.name):
            _pushed_items(monkeypatch)
        lines = [r.getMessage() for r in caplog.records if "[ATTACK-SAME-NAME]" in r.getMessage()]
        # 2026-11-08: the deprecated ICS copy's id is its ``mitre-ics-attack`` one (``_attack_external_id``).
        assert any("'Killdisk' (ics, S1005) for 'KillDisk' (ics, S0607)" in line for line in lines)
        assert any("'TRITON' (enterprise, S0609) for 'Triton' (ics, S1009)" in line for line in lines)

    def test_a_left_out_object_with_links_of_its_own_is_warned_about(self, monkeypatch, caplog):
        """No ATT&CK copy has links of its own (no warning on the real objects); one that had would warn."""
        with caplog.at_level(logging.WARNING, logger=mc.logger.name):
            _pushed_items(monkeypatch)
        assert not [r for r in caplog.records if "[ATTACK-SAME-NAME]" in r.getMessage()]
        items = [
            {"name": "KillDisk", "mitre_id": "S0607", "deprecated": False, "uses_techniques": ["T1485"]},
            {"name": "Killdisk", "deprecated": True, "uses_techniques": ["T1485", "T0809"]},
        ]
        with caplog.at_level(logging.WARNING, logger=mc.logger.name):
            assert mc._one_item_per_node_key(items, "Malware") == items[:1]
        assert any("with a technique or software link the kept item lacks" in r.getMessage() for r in caplog.records)

    def test_a_group_in_both_bundles_unites_its_software_links(self, monkeypatch):
        """TEMP.Veles is one STIX object in both bundles: Enterprise gives Mimikatz, ICS gives Triton."""
        temp_veles = _by_key(_of(_pushed_items(monkeypatch), "actor"))["temp.veles"]
        assert temp_veles["attack_domain"] == "enterprise"
        assert temp_veles["uses_tools"] == ["S0002"]
        assert temp_veles["uses_malware"] == ["Triton"]

    def test_tools_are_grouped_by_their_attack_id(self):
        """``Tool`` nodes are keyed by their ATT&CK id: tools of one name and two ids stay two items, even
        a deprecated one beside an active one; one id from both bundles becomes one item."""
        tools = [
            {"type": "tool", "name": "Ngrok", "mitre_id": "S9000", "deprecated": True, "uses_techniques": ["T1"]},
            {"type": "tool", "name": "Ngrok", "mitre_id": "S0508", "deprecated": False, "uses_techniques": ["T2"]},
            {"type": "tool", "name": "Ngrok", "mitre_id": "S0508", "deprecated": False, "uses_techniques": ["T3"]},
        ]
        kept = mc._one_item_per_node_key(tools, "Tool")
        assert [(t["mitre_id"], t["uses_techniques"]) for t in kept] == [("S9000", ["T1"]), ("S0508", ["T2", "T3"])]


class TestIcsBundleFailure:
    def test_no_deprecated_group_or_malware_is_pushed_and_the_etag_is_not_stored(self, monkeypatch, caplog):
        """Without the ICS bundle the run cannot tell that the deprecated TRITON has an active namesake."""
        collector, writer = _collector(monkeypatch, ics_fails=True, etag='"enterprise-v1"')
        with caplog.at_level(logging.WARNING, logger=mc.logger.name):
            status = collector.collect(push_to_misp=True, baseline=False)
        assert status["success"] is True
        (items,), _ = writer.push_items.call_args
        assert {it["name"] for it in _of(items, "malware")} == {"KillDisk"}
        assert not [it for it in items if it.get("deprecated") and it["type"] in ("actor", "malware")]
        assert collector.stored_etags == []
        assert any(
            "ATT&CK for ICS failed: 1 deprecated group(s) / malware held back" in r.getMessage() for r in caplog.records
        )

    def test_with_both_bundles_the_etag_is_stored(self, monkeypatch):
        collector, _ = _collector(monkeypatch, etag='"enterprise-v1"')
        assert collector.collect(push_to_misp=True, baseline=False)["success"] is True
        assert collector.stored_etags == ['"enterprise-v1"']


# --------------------------------------------------------------------------- 2. ATT&CK ids
class TestAttackIdsOfGroupsAndMalware:
    def test_the_collector_items_carry_the_ids(self, monkeypatch):
        items = _pushed_items(monkeypatch)
        actors = _by_key(_of(items, "actor"))
        assert actors["apt38"]["mitre_id"] == "G0082" and actors["apt38"]["uses_malware"] == ["KillDisk"]
        assert actors["temp.veles"]["mitre_id"] == "G0088" and actors["temp.veles"]["uses_malware"] == ["Triton"]

    @pytest.mark.parametrize(
        "item_type, name, attack_id, create",
        [
            ("actor", "TEMP.Veles", "G0088", "create_actor_attribute"),
            ("malware", "Triton", "S1009", "create_malware_attribute"),
        ],
    )
    def test_the_id_travels_through_misp_to_the_node_and_its_source_refs(
        self, monkeypatch, item_type, name, attack_id, create
    ):
        item = next(it for it in _pushed_items(monkeypatch) if it["type"] == item_type and it["name"] == name)
        attribute = getattr(_writer(), create)(item)
        assert attribute["value"] == name, "the MISP value stays the name, the node key"
        assert f'"aid":"{attack_id}"' in attribute["comment"].split("\n", 1)[0]

        parsed, _ = _syncer().parse_attribute(_as_stored(attribute, 1), EVENT)
        assert parsed["mitre_id"] == attack_id
        assert parsed["source_refs"] == [f"mitre_attck:{attack_id}"]

        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        session = client.driver.session.return_value.__enter__.return_value
        session.run.return_value.single.return_value = None  # no existing node
        client._upsert_sourced_relationship = MagicMock(return_value=True)
        merge = client.merge_actor if item_type == "actor" else client.merge_malware
        assert merge(parsed, source_id="mitre_attck") is True
        query, params = session.run.call_args.args[0], session.run.call_args.kwargs
        assert "n.mitre_id = $mitre_id" in query and params["mitre_id"] == attack_id
        assert "n.deprecated = $deprecated" in query and params["deprecated"] is False
        assert params["name"] == name.lower(), "the node stays keyed by the lower-cased name"
        assert client._upsert_sourced_relationship.call_args.kwargs["source_refs"] == [f"mitre_attck:{attack_id}"]

    @pytest.mark.parametrize(
        "item_type, name, create, merge, rank",
        [
            ("malware", "Triton", "create_malware_attribute", "merge_malware", 2),
            ("actor", "TEMP.Veles", "create_actor_attribute", "merge_actor", 3),
        ],
    )
    def test_an_item_with_an_attack_id_is_merged_by_its_type_not_as_a_technique(
        self, monkeypatch, item_type, name, create, merge, rank
    ):
        item = next(it for it in _pushed_items(monkeypatch) if it["type"] == item_type and it["name"] == name)
        parsed, _ = _syncer().parse_attribute(_as_stored(getattr(_writer(), create)(item), 1), EVENT)
        assert parsed["mitre_id"]
        syncer = _syncer()
        syncer._sync_to_neo4j_chunk([parsed])
        getattr(syncer.neo4j, merge).assert_called_once()
        syncer.neo4j.merge_technique.assert_not_called()

        import run_misp_to_neo4j as sync_mod

        assert sync_mod._neo4j_sync_item_sort_rank(parsed) == rank
        # An attribute written before the id was carried names the same node: one item per name.
        older = {k: v for k, v in parsed.items() if k not in ("mitre_id", "source_refs")}
        assert len(sync_mod._dedupe_parsed_items([parsed, older])) == 1

    @pytest.mark.parametrize(
        "item_type, name, create",
        [("malware", "Triton", "create_malware_attribute"), ("actor", "TEMP.Veles", "create_actor_attribute")],
    )
    def test_an_id_is_taken_from_an_attack_attribute_only(self, monkeypatch, item_type, name, create):
        item = next(it for it in _pushed_items(monkeypatch) if it["type"] == item_type and it["name"] == name)
        attribute = _as_stored(getattr(_writer(), create)({**item, "tag": "alienvault_otx"}), 1)
        assert '"aid":' in attribute["comment"]
        parsed, _ = _syncer().parse_attribute(attribute, EVENT)
        assert "mitre_id" not in parsed and not parsed.get("source_refs")

    def test_a_malformed_id_is_not_written(self):
        from attack_values import attack_object_id

        assert attack_object_id("actor", " g0088 ") == "G0088"
        assert attack_object_id("malware", "S1009") == "S1009"
        for kind, value in (("actor", "S1009"), ("malware", "G0088"), ("tool", "S0002"), ("malware", "S10090")):
            assert attack_object_id(kind, value) == ""
        assert attack_object_id("malware", None) == ""


# --------------------------------------------------------------------------- 3. push confirmation
def _misp_writer_answering(monkeypatch, stored: list):
    """``MISPWriter`` whose session answers every event edit with HTTP 200 and an event holding ``stored``."""
    writer = mw.MISPWriter(url="https://misp.test", api_key="test-key", verify_ssl=True)

    class _Response:
        status_code = 200
        text = ""

        def json(self):
            return {"Event": {"id": "40", "Attribute": deepcopy(stored)}}

    class _Session:
        def post(self, url, json=None, **_kwargs):
            return _Response()

    writer.session = _Session()
    monkeypatch.setattr(mw.time, "sleep", lambda *_a, **_k: None)
    return writer


class TestPushConfirmation:
    def _triton_attribute(self, monkeypatch) -> dict:
        item = next(it for it in _pushed_items(monkeypatch) if it["type"] == "malware" and it["name"] == "Triton")
        return _writer().create_malware_attribute(item)

    def test_a_value_the_event_holds_in_another_case_is_not_confirmed(self, monkeypatch):
        confirmed, unconfirmed = mw._confirm_pushed_attributes([self._triton_attribute(monkeypatch)], _MISP_STORED)
        assert (confirmed, unconfirmed) == (0, [("malware-type", "Triton")])

    def test_each_value_misp_stored_confirms_itself_only(self):
        """MISP stored both KillDisk and Killdisk: each confirms itself; a third case variant is not stored."""
        pushed = [{"type": "malware-type", "value": v} for v in ("KillDisk", "Killdisk", "KILLDISK")]
        assert mw._confirm_pushed_attributes(pushed, _MISP_STORED) == (2, [("malware-type", "KILLDISK")])

    @pytest.mark.parametrize(
        "attr_type, pushed, stored",
        [
            ("threat-actor", "TEMP.Veles", "Temp.Veles"),
            ("text", "S1009 - Triton", "S1009 - TRITON"),
            ("url", "http://198.51.100.7/Mozi.m", "http://198.51.100.7/mozi.m"),
            ("filename", "Invoice.EXE", "invoice.exe"),
            ("regkey", "HKLM\\Software\\Run", "HKLM\\SOFTWARE\\Run"),
        ],
    )
    def test_a_type_misp_stores_as_given_is_compared_exactly(self, attr_type, pushed, stored):
        assert mw._confirm_pushed_attributes(
            [{"type": attr_type, "value": pushed}], [{"type": attr_type, "value": stored}]
        ) == (0, [(attr_type, pushed)])

    def test_push_batch_reports_the_value_misp_did_not_store(self, monkeypatch, caplog):
        monkeypatch.delenv("EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING", raising=False)
        writer = _misp_writer_answering(monkeypatch, _MISP_STORED)
        with caplog.at_level(logging.WARNING, logger=mw.logger.name):
            assert writer._push_batch("40", [self._triton_attribute(monkeypatch)]) == (1, 0)
        assert writer.stats["attributes_unconfirmed"] == 1
        assert any("[UNCONFIRMED]" in r.getMessage() and "'Triton'" in r.getMessage() for r in caplog.records)

        monkeypatch.setenv("EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING", "true")
        writer = _misp_writer_answering(monkeypatch, _MISP_STORED)
        assert writer._push_batch("40", [self._triton_attribute(monkeypatch)]) == (0, 1)

    @pytest.mark.parametrize(
        "pushed, stored",
        [
            ("ABCDEF" + "0" * 58, "abcdef" + "0" * 58),  # sha256: MISP lower-cases hashes
            ("Malicious.Example", "malicious.example"),  # domain: lower-cased
            ("cve-2024-3400", "CVE-2024-3400"),  # vulnerability: upper-cased
            ("2001:DB8::7", "2001:db8::7"),  # ip-dst: an IPv6 address is written in lower case
            ("EXAMPLE.org", "example.org"),  # hostname: lower-cased
            ("AB:CD:" + "0" * 36, "ab:cd:" + "0" * 36),  # x509-fingerprint-sha1: lower-cased
        ],
    )
    def test_values_misp_normalises_are_still_confirmed(self, pushed, stored):
        attr_type = {
            "A": "sha256",
            "M": "domain",
            "c": "vulnerability",
            "2": "ip-dst",
            "E": "hostname",
        }.get(pushed[0], "x509-fingerprint-sha1")
        assert mw._confirm_pushed_attributes(
            [{"type": attr_type, "value": pushed}], [{"type": attr_type, "value": stored}]
        ) == (1, [])


# --------------------------------------------------------------------------- 4. the flag per caller
class TestDeprecatedFlagPerCaller:
    """Only an ATT&CK record clears ``n.deprecated``; the other callers of the merge never clear it."""

    @staticmethod
    def _client():
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.merge_node_with_source = MagicMock(return_value=True)
        return client

    def test_an_otx_malware_attribute_does_not_clear_the_flag(self):
        """The real OTX attribute of ``tests/fixtures/otx_entity_attributes_2026_10_09.json``."""
        real = json.loads((FIXTURES / "otx_entity_attributes_2026_10_09.json").read_text(encoding="utf-8"))
        attr = next(a for a in real["attributes"] if a["type"] == "malware-type")
        stored = {**attr, "uuid": "00000000-0000-4000-8000-000000000003", "Tag": [{"name": t} for t in attr["tags"]]}
        parsed, _ = _syncer().parse_attribute(stored, {"id": "41", "info": "EdgeGuard-alienvault_otx-2026-10-09"})
        assert parsed["tag"] == "alienvault_otx" and parsed["deprecated"] is False
        client = self._client()
        assert client.merge_malware(parsed, source_id=parsed["tag"])
        assert "deprecated" not in client.merge_node_with_source.call_args.kwargs["extra_props"]
