"""ATT&CK software's MISP galaxy and the ATT&CK for ICS ids of deprecated objects (2026-11-08).

The 730-day baseline of 2026-11-08 on the project's test MISP showed two gaps in the ATT&CK cards MISP attaches:

1. MISPWriter tagged ATT&CK software with the ``mitre-malware`` / ``mitre-tool`` galaxies. The MISP galaxy
   repository merged them (and the ICS software) into ``mitre-software`` on 2026-08-30 and updates only that one
   since, so 23 malware tags had no cluster. The writer now reads MISP's galaxy list once per writer, the first
   time a push holds a malware or tool item with an ATT&CK id, and tags software with ``mitre-software`` when MISP
   has that galaxy enabled; otherwise, and on any failure, with the two old galaxies. Groups keep
   ``mitre-intrusion-set``. Nothing the sync reads changes: the node type comes from the attribute's type and
   value, never from an ATT&CK galaxy tag.
2. The MITRE collector read an object's ATT&CK id only from a ``mitre-attack`` reference. 19 deprecated objects
   of the ICS bundle have only a ``mitre-ics-attack`` one: ``BlackEnergy 3`` reached MISP without its id
   (S1002), and 12 deprecated ICS techniques were skipped. One helper (``_attack_external_id``) now reads the
   ``mitre-attack`` id, else the ``mitre-ics-attack`` one, at every place the collector reads an id. The rule for
   revoked and deprecated objects is unchanged: the 12 techniques are kept and marked deprecated, and the
   deprecated ICS copies of active software are still left out beside it.

Fixture: ``tests/fixtures/attack_software_galaxy_and_ics_ids_2026_11_08.json`` (real STIX objects of the ATT&CK
20.1 bundles, the ATT&CK rows of the test MISP's ``GET /galaxies/index`` answer and real galaxy clusters), and
``tests/fixtures/attack_source_text_objects_2026_11_07.json`` for an Enterprise malware and tool. Where a test
changes an object, it says so.
"""

from __future__ import annotations

import copy
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from collectors import misp_writer as mw  # noqa: E402
from collectors import mitre_collector as mc  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

FIXTURE = json.loads(
    (TESTS / "fixtures" / "attack_software_galaxy_and_ics_ids_2026_11_08.json").read_text(encoding="utf-8")
)
TEXT_FIXTURE = json.loads(
    (TESTS / "fixtures" / "attack_source_text_objects_2026_11_07.json").read_text(encoding="utf-8")
)
EVENT = {"id": "601", "info": "EdgeGuard-mitre_attck-2026-11-08", "Tag": []}
SOFTWARE = "mitre-software"


def _object(bundle: str, attack_id: str) -> Dict[str, Any]:
    (obj,) = [
        o
        for o in FIXTURE[bundle]
        if any(e.get("external_id") == attack_id for e in o.get("external_references") or [] if isinstance(e, dict))
    ]
    return copy.deepcopy(obj)


def _parsed(objects: List[Dict[str, Any]], domain: str = mc.ATTACK_DOMAIN_ICS) -> Dict[str, list]:
    kill_chain = mc.ICS_KILL_CHAIN_NAME if domain == mc.ATTACK_DOMAIN_ICS else mc.ENTERPRISE_KILL_CHAIN_NAME
    collector = mc.MITRECollector(misp_writer=MagicMock())
    return collector._parse_bundle(copy.deepcopy(objects), domain=domain, kill_chain_name=kill_chain)


def _ics_items() -> Dict[str, list]:
    return _parsed(FIXTURE["ics"])


def _one(items: List[Dict[str, Any]], name: str) -> Dict[str, Any]:
    (item,) = [i for i in items if i.get("name") == name]
    return item


def _text_item(kind: str, attack_id: str) -> Dict[str, Any]:
    """An Enterprise item of the 2026-11-07 fixture, as the collector emits it."""
    key = {"malware": "malware", "tool": "tools", "actor": "actors"}[kind]
    parsed = _parsed(TEXT_FIXTURE["enterprise"], domain=mc.ATTACK_DOMAIN_ENTERPRISE)
    (item,) = [i for i in parsed[key] if i.get("mitre_id") == attack_id]
    return item


def _clusters(value: str) -> Dict[str, Dict[str, Any]]:
    """The test MISP's clusters of *value*, by galaxy."""
    return {c["galaxy"]: c for c in FIXTURE["galaxy_clusters"][value]}


def _writer(galaxy: Any = None) -> mw.MISPWriter:
    """A writer that already knows the software galaxy (None: the old galaxies)."""
    writer = mw.MISPWriter.__new__(mw.MISPWriter)
    writer._attack_software_galaxy = galaxy
    writer._attack_software_galaxy_read = True
    return writer


def _galaxy_tags(attribute: Dict[str, Any]) -> List[str]:
    return [t["name"] for t in attribute["Tag"] if t["name"].startswith("misp-galaxy:mitre-")]


def _stored(attribute: Dict[str, Any]) -> Dict[str, Any]:
    """*attribute* as MISP lists it (a uuid, the event id)."""
    out = copy.deepcopy(attribute)
    out.update(uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, attribute["value"])), event_id="601", timestamp="1")
    return out


# ================================================================================ 1. the ATT&CK id of an object
class TestAttackExternalId:
    @pytest.mark.parametrize(
        ("bundle", "attack_id"),
        [
            ("ics", "S1002"),
            ("ics", "T0850"),
            ("ics", "T0833"),
            ("ics", "T0881"),
            ("ics", "S1009"),
            ("enterprise", "T1051"),
        ],
    )
    def test_the_id_of_each_real_object(self, bundle, attack_id):
        assert mc._attack_external_id(_object(bundle, attack_id)) == attack_id

    def test_the_ics_only_objects_have_no_mitre_attack_reference(self):
        """The fixture's deprecated ICS objects carry their id only in a ``mitre-ics-attack`` reference."""
        for attack_id in ("S1002", "T0850", "T0833"):
            sources = {e.get("source_name") for e in _object("ics", attack_id)["external_references"]}
            assert "mitre-ics-attack" in sources and "mitre-attack" not in sources

    def test_a_mitre_attack_id_wins_wherever_it_is_listed(self):
        """Constructed: a ``mitre-ics-attack`` reference put before the ``mitre-attack`` one of Service Stop."""
        obj = _object("ics", "T0881")
        obj["external_references"].insert(0, {"source_name": "mitre-ics-attack", "external_id": "T0999"})
        assert mc._attack_external_id(obj) == "T0881"

    def test_a_capec_id_is_never_the_attack_id(self):
        """Shared Webroot lists ``CAPEC-563``; without its ``mitre-attack`` reference (constructed) it has no id."""
        obj = _object("enterprise", "T1051")
        assert mc._attack_external_id(obj) == "T1051"
        obj["external_references"] = [e for e in obj["external_references"] if e.get("source_name") != "mitre-attack"]
        assert any(e.get("external_id") == "CAPEC-563" for e in obj["external_references"])
        assert mc._attack_external_id(obj) == ""

    def test_a_mobile_id_is_not_read(self):
        """``mitre-mobile-attack`` is not one of the names read: the Mobile bundle is not collected, and its objects
        with only that name are revoked."""
        obj = _object("mobile", "T1425")
        assert obj.get("revoked") is True
        assert mc._attack_external_id(obj) == ""

    @pytest.mark.parametrize(
        "refs",
        [
            [],
            [{"source_name": "mitre-ics-attack", "external_id": ""}],
            [{"source_name": "mitre-attack"}],
            ["mitre-attack", None, 5],
        ],
    )
    def test_references_without_an_id_give_none(self, refs):
        assert mc._attack_external_id({"type": "malware", "external_references": refs}) == ""

    def test_an_empty_mitre_attack_reference_falls_back_to_the_ics_id(self):
        """Constructed: a ``mitre-attack`` reference without ``external_id`` does not hide the ICS one."""
        refs = [{"source_name": "mitre-attack"}, {"source_name": "mitre-ics-attack", "external_id": "S1002"}]
        assert mc._attack_external_id({"external_references": refs}) == "S1002"


# ================================================================================ 2. every caller in the collector
def _ics_only(obj: Dict[str, Any], attack_id: str) -> Dict[str, Any]:
    """Constructed: *obj* with its ``mitre-attack`` id moved to a ``mitre-ics-attack`` reference."""
    out = copy.deepcopy(obj)
    out["external_references"] = [{"source_name": "mitre-ics-attack", "external_id": attack_id}] + [
        e for e in out["external_references"] if e.get("source_name") != "mitre-attack"
    ]
    return out


class TestEveryCollectorPathReadsTheIcsId:
    def test_deprecated_ics_techniques_are_kept_and_marked(self):
        techniques = {t["mitre_id"]: t for t in _ics_items()["techniques"]}
        assert sorted(techniques) == ["T0833", "T0850", "T0881"]
        role = techniques["T0850"]
        assert (role["name"], role["deprecated"], role["attack_domain"]) == ("Role Identification", True, "ics")
        assert role["tactic_phases"] == ["collection"]
        assert techniques["T0833"]["tactic_phases"] == ["impair-process-control", "inhibit-response-function"]
        assert techniques["T0881"]["deprecated"] is False

    def test_blackenergy_3_carries_its_id_and_stays_deprecated(self):
        item = _one(_ics_items()["malware"], "BlackEnergy 3")
        assert (item["mitre_id"], item["deprecated"], item["attack_domain"]) == ("S1002", True, "ics")

    def test_a_tool_with_only_an_ics_id_is_kept(self):
        """Constructed: no tool of ATT&CK 20.1 has only an ICS id; Net's id moved to such a reference."""
        (net,) = [o for o in TEXT_FIXTURE["enterprise"] if o.get("type") == "tool" and o.get("name") == "Net"]
        tools = _parsed([_ics_only(net, "S0039")], domain=mc.ATTACK_DOMAIN_ENTERPRISE)["tools"]
        assert [(t["name"], t["mitre_id"]) for t in tools] == [("Net", "S0039")]

    def test_a_tool_without_any_id_is_still_skipped(self):
        """Negative: the fallback does not keep a tool that has neither reference (constructed)."""
        (net,) = [o for o in TEXT_FIXTURE["enterprise"] if o.get("type") == "tool" and o.get("name") == "Net"]
        net = copy.deepcopy(net)
        net["external_references"] = [e for e in net["external_references"] if e.get("source_name") != "mitre-attack"]
        assert _parsed([net], domain=mc.ATTACK_DOMAIN_ENTERPRISE)["tools"] == []

    def test_a_tactic_and_a_group_with_only_an_ics_id_carry_it(self):
        """Constructed: the ICS tactics and groups of ATT&CK 20.1 have ``mitre-attack`` ids."""
        tactic = {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--00000000-0000-4000-8000-000000000001",
            "name": "Collection",
            "x_mitre_shortname": "collection",
            "description": "",
            "external_references": [{"source_name": "mitre-ics-attack", "external_id": "TA0100"}],
        }
        group = {
            "type": "intrusion-set",
            "id": "intrusion-set--00000000-0000-4000-8000-000000000002",
            "name": "Example Group",
            "description": "",
            "external_references": [{"source_name": "mitre-ics-attack", "external_id": "G0999"}],
        }
        parsed = _parsed([tactic, group])
        assert [t["mitre_id"] for t in parsed["tactics"]] == ["TA0100"]
        assert [a["mitre_id"] for a in parsed["actors"]] == ["G0999"]

    def test_a_uses_link_to_a_technique_with_only_an_ics_id_is_kept(self):
        """Constructed relationship (the real deprecated techniques have none): Triton uses Role Identification.
        Before, the technique had no id in the relationship map and the link was dropped."""
        triton, role = _object("ics", "S1009"), _object("ics", "T0850")
        rel = {
            "type": "relationship",
            "id": "relationship--00000000-0000-4000-8000-000000000003",
            "relationship_type": "uses",
            "source_ref": triton["id"],
            "target_ref": role["id"],
        }
        parsed = _parsed([triton, role, rel])
        assert "T0850" in _one(parsed["malware"], "Triton")["uses_techniques"]

    def test_a_revoked_technique_with_only_an_ics_id_is_named_by_it(self, monkeypatch):
        """Constructed: Role Identification revoked and absent from the revoked-id map: kept, and the warning
        names its ATT&CK id."""
        role = _object("ics", "T0850")
        role["revoked"] = True
        stix_ids, attack_ids = mc._revoked_techniques_without_successor_in_map([role], {role["id"]})
        assert stix_ids == {role["id"]} and attack_ids == ["T0850"]


class TestTheDeprecatedRuleIsUnchanged:
    def test_a_deprecated_ics_copy_is_still_left_out_beside_the_active_object(self, caplog):
        """Constructed: a deprecated copy of Triton with only an ICS id (as ``Killdisk`` S1005 is published beside
        ``KillDisk``): left out, and the log names both ids."""
        triton = _object("ics", "S1009")
        copy_ = _ics_only(triton, "S1099")
        copy_.update(id="malware--00000000-0000-4000-8000-000000000004", x_mitre_deprecated=True, name="TRITON")
        with caplog.at_level(logging.INFO, logger=mc.logger.name):
            malware = _parsed([triton, copy_])["malware"]
        assert [(m["name"], m["mitre_id"], m["deprecated"]) for m in malware] == [("Triton", "S1009", False)]
        assert any("'TRITON' (ics, S1099) for 'Triton' (ics, S1009)" in r.getMessage() for r in caplog.records)

    def test_a_deprecated_ics_technique_reaches_misp_marked_and_with_its_cluster(self):
        technique = {t["mitre_id"]: t for t in _ics_items()["techniques"]}["T0850"]
        attribute = _writer().create_technique_attribute(copy.deepcopy(technique))
        tags = [t["name"] for t in attribute["Tag"]]
        assert attribute["value"] == "T0850 - Role Identification"
        assert mw.ATTACK_DEPRECATED_TAG in tags and "attack-domain:ics" in tags
        assert 'misp-galaxy:mitre-attack-pattern="Role Identification - T0850"' in tags
        item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(_stored(attribute), EVENT)
        assert (item["type"], item["mitre_id"], item["deprecated"]) == ("technique", "T0850", True)

    def test_blackenergy_3_reaches_the_node_with_its_id(self):
        item = _one(_ics_items()["malware"], "BlackEnergy 3")
        attribute = _writer(SOFTWARE).create_malware_attribute(copy.deepcopy(item))
        assert '"aid":"S1002"' in attribute["comment"].split("\n", 1)[0]
        assert _galaxy_tags(attribute) == [_clusters("BlackEnergy 3 - S1002")[SOFTWARE]["tag_name"]]
        parsed, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(_stored(attribute), EVENT)
        assert (parsed["type"], parsed["mitre_id"], parsed["deprecated"]) == ("malware", "S1002", True)
        assert parsed["source_refs"] == ["mitre_attck:S1002"]


# ================================================================================ 3. the software galaxy tag
class TestTheSoftwareGalaxyTag:
    @pytest.mark.parametrize(
        ("kind", "attack_id", "value"),
        [
            ("malware", "S1072", "Industroyer2 - S1072"),
            ("tool", "S0039", "Net - S0039"),
            ("tool", "S0363", "Empire - S0363"),
        ],
    )
    def test_software_gets_the_cluster_tag_of_the_software_galaxy(self, kind, attack_id, value):
        build = {"malware": "create_malware_attribute", "tool": "create_tool_attribute"}[kind]
        attribute = getattr(_writer(SOFTWARE), build)(_text_item(kind, attack_id))
        clusters = _clusters(value)
        assert _galaxy_tags(attribute) == [clusters[SOFTWARE]["tag_name"]]  # the tag the cluster carries, exactly
        legacy = getattr(_writer(None), build)(_text_item(kind, attack_id))
        old = clusters["mitre-malware" if kind == "malware" else "mitre-tool"]
        assert _galaxy_tags(legacy) == [old["tag_name"]]
        # The same card: the merged galaxy's cluster has the old cluster's value and uuid.
        assert (clusters[SOFTWARE]["value"], clusters[SOFTWARE]["uuid"]) == (old["value"], old["uuid"])

    def test_the_ics_software_has_a_cluster_only_in_the_software_galaxy(self):
        assert set(_clusters("BlackEnergy 3 - S1002")) == {SOFTWARE}
        assert set(_clusters("Triton - S1009")) == {SOFTWARE}
        item = _one(_ics_items()["malware"], "Triton")
        assert _galaxy_tags(_writer(SOFTWARE).create_malware_attribute(item)) == [
            _clusters("Triton - S1009")[SOFTWARE]["tag_name"]
        ]

    def test_a_group_keeps_its_galaxy(self):
        """Negative: the software galaxy does not apply to groups."""
        actor = _text_item("actor", "G0034")
        tags = _galaxy_tags(_writer(SOFTWARE).create_actor_attribute(actor))
        assert tags == ['misp-galaxy:mitre-intrusion-set="Sandworm Team - G0034"']

    @pytest.mark.parametrize(
        "item",
        [
            {"type": "malware", "name": "Industroyer2", "tag": "alienvault_otx"},
            {"type": "malware", "name": "X", "tag": "mitre_attck", "mitre_id": "G0034"},
        ],
    )
    def test_software_without_an_id_gets_no_cluster_tag(self, item):
        """Negative: an OTX family or a wrong-kind id gets no ATT&CK cluster with either galaxy (constructed)."""
        assert _galaxy_tags(_writer(SOFTWARE).create_malware_attribute(dict(item))) == []

    def test_the_helper_keeps_the_old_galaxies_without_a_software_galaxy(self):
        item = {"type": "malware", "name": "BlackEnergy 3", "mitre_id": "S1002"}
        assert mw._attack_galaxy_tags(item, "BlackEnergy 3") == ['misp-galaxy:mitre-malware="BlackEnergy 3 - S1002"']
        assert mw._attack_galaxy_tags(item, "BlackEnergy 3", SOFTWARE) == [
            'misp-galaxy:mitre-software="BlackEnergy 3 - S1002"'
        ]


class TestGalaxyListAnswer:
    def test_the_test_misps_answer_lists_the_software_galaxy(self):
        rows = FIXTURE["galaxies_index_rows"]
        assert mw._misp_lists_galaxy(rows, SOFTWARE) is True
        assert mw._misp_lists_galaxy({"response": rows}, SOFTWARE) is True

    def test_an_answer_without_it_does_not(self):
        rows = [r for r in FIXTURE["galaxies_index_rows"] if r["Galaxy"]["type"] != SOFTWARE]
        assert mw._misp_lists_galaxy(rows, SOFTWARE) is False

    @pytest.mark.parametrize("enabled", [False, 0, "0", "false"])
    def test_a_disabled_galaxy_does_not_count(self, enabled):
        rows = copy.deepcopy(FIXTURE["galaxies_index_rows"])
        for r in rows:
            if r["Galaxy"]["type"] == SOFTWARE:
                r["Galaxy"]["enabled"] = enabled
        assert mw._misp_lists_galaxy(rows, SOFTWARE) is False

    def test_a_row_without_the_enabled_field_counts(self):
        rows = copy.deepcopy(FIXTURE["galaxies_index_rows"])
        for r in rows:
            r["Galaxy"].pop("enabled")
        assert mw._misp_lists_galaxy(rows, SOFTWARE) is True

    @pytest.mark.parametrize("answer", [None, "text", {"Galaxy": []}, {"response": "x"}, [None, 5, "mitre-software"]])
    def test_other_answers_do_not(self, answer):
        assert mw._misp_lists_galaxy(answer, SOFTWARE) is False


# ================================================================================ 4. read once, through push_items
class _FakeMisp:
    """MISP behind ``MISPWriter.session``: the day's event exists and holds nothing; ``galaxies`` answers
    ``GET /galaxies/index`` (an exception instance is raised, an int is the HTTP status of an empty answer)."""

    def __init__(self, galaxies: Any):
        self.galaxies = galaxies
        self.gets: List[str] = []

    def get(self, url: str, **_kwargs: Any) -> MagicMock:
        self.gets.append(url)
        assert url.endswith("/galaxies/index"), url
        if isinstance(self.galaxies, Exception):
            raise self.galaxies
        if isinstance(self.galaxies, int):
            return MagicMock(status_code=self.galaxies, text="")
        r = MagicMock(status_code=200, text="")
        if self.galaxies == "not json":
            r.json.side_effect = ValueError("Expecting value")
        else:
            r.json.return_value = self.galaxies
        return r

    def post(self, url: str, json: Any = None, **_kwargs: Any) -> MagicMock:
        r = MagicMock(status_code=200, text="")
        if url.endswith("/events/restSearch"):
            # The day's event of the source asked for exists.
            r.json.return_value = {"response": [{"Event": {"id": "77", "info": (json or {}).get("eventinfo")}}]}
        elif url.endswith("/attributes/restSearch"):
            r.json.return_value = {"response": {"Attribute": []}}
        else:  # pragma: no cover
            raise AssertionError(f"unexpected MISP request {url}")
        return r


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setattr(mw, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", True)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.delenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", raising=False)
    monkeypatch.setattr(mw.time, "sleep", lambda _s: None)


def _pushing_writer(monkeypatch, galaxies: Any):
    writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    misp = _FakeMisp(galaxies)
    writer.session = misp
    pushed: List[Dict[str, Any]] = []

    def push_batch(_event_id, batch):
        pushed.extend(batch)
        return len(batch), 0

    monkeypatch.setattr(writer, "_push_batch", push_batch)
    return writer, misp, pushed


def _software_items() -> List[Dict[str, Any]]:
    return [_text_item("malware", "S1072"), _text_item("tool", "S0039")]


def _pushed_galaxy_tags(pushed: List[Dict[str, Any]]) -> List[str]:
    return sorted(t for a in pushed for t in _galaxy_tags(a))


class TestTheGalaxyIsReadOncePerWriter:
    def test_a_misp_with_the_galaxy_gets_software_galaxy_tags(self, monkeypatch, caplog):
        writer, misp, pushed = _pushing_writer(monkeypatch, FIXTURE["galaxies_index_rows"])
        with caplog.at_level(logging.INFO, logger=mw.logger.name):
            assert writer.push_items(_software_items()) == (2, 0)
        assert _pushed_galaxy_tags(pushed) == [
            _clusters("Industroyer2 - S1072")[SOFTWARE]["tag_name"],
            _clusters("Net - S0039")[SOFTWARE]["tag_name"],
        ]
        assert misp.gets == ["https://misp.test/galaxies/index"]
        assert any("tagged with the mitre-software galaxy" in r.getMessage() for r in caplog.records)

    def test_a_second_push_does_not_read_the_list_again(self, monkeypatch):
        writer, misp, pushed = _pushing_writer(monkeypatch, FIXTURE["galaxies_index_rows"])
        writer.push_items([_text_item("malware", "S1072")])
        writer.push_items([_text_item("tool", "S0039")])
        assert len(misp.gets) == 1
        assert all(t.startswith("misp-galaxy:mitre-software=") for t in _pushed_galaxy_tags(pushed))

    def test_a_misp_without_the_galaxy_keeps_the_old_galaxies(self, monkeypatch):
        rows = [r for r in FIXTURE["galaxies_index_rows"] if r["Galaxy"]["type"] != SOFTWARE]
        writer, misp, pushed = _pushing_writer(monkeypatch, rows)
        writer.push_items(_software_items())
        assert _pushed_galaxy_tags(pushed) == [
            _clusters("Industroyer2 - S1072")["mitre-malware"]["tag_name"],
            _clusters("Net - S0039")["mitre-tool"]["tag_name"],
        ]
        assert len(misp.gets) == 1

    @pytest.mark.parametrize(
        "galaxies",
        [500, 403, ConnectionError("refused"), "not json"],
        ids=["http-500", "http-403", "no-answer", "not-json"],
    )
    def test_a_failed_read_keeps_the_old_galaxies_and_is_not_repeated(self, monkeypatch, caplog, galaxies):
        writer, misp, pushed = _pushing_writer(monkeypatch, galaxies)
        with caplog.at_level(logging.WARNING, logger=mw.logger.name):
            writer.push_items([_text_item("malware", "S1072")])
            writer.push_items([_text_item("tool", "S0039")])
        assert _pushed_galaxy_tags(pushed) == [
            _clusters("Industroyer2 - S1072")["mitre-malware"]["tag_name"],
            _clusters("Net - S0039")["mitre-tool"]["tag_name"],
        ]
        assert len(misp.gets) == 1
        (line,) = [r.getMessage() for r in caplog.records if "[ATTACK-GALAXY]" in r.getMessage()]
        assert "could not be read" in line

    def test_a_push_without_attack_software_sends_no_request(self, monkeypatch):
        """Negative: an OTX family, a group, a technique and an indicator need no software galaxy."""
        items = [
            {"type": "malware", "name": "Emotet", "tag": "alienvault_otx", "zone": ["global"]},
            _text_item("actor", "G0034"),
            {"type": "technique", "mitre_id": "T1059.003", "name": "Windows Command Shell", "tag": "mitre_attck"},
            {"indicator_type": "domain", "value": "evil.example.com", "tag": "alienvault_otx", "zone": ["global"]},
        ]
        writer, misp, pushed = _pushing_writer(monkeypatch, FIXTURE["galaxies_index_rows"])
        assert writer.push_items(items) == (4, 0)
        assert misp.gets == []
        assert writer._attack_software_galaxy_read is False
        assert _pushed_galaxy_tags(pushed) == [
            'misp-galaxy:mitre-attack-pattern="Windows Command Shell - T1059.003"',
            'misp-galaxy:mitre-intrusion-set="Sandworm Team - G0034"',
        ]


# ================================================================================ 5. the sync reads it as before
class TestTheSyncReadsTheSoftwareTagAsBefore:
    @pytest.mark.parametrize(("kind", "attack_id"), [("malware", "S1072"), ("tool", "S0039"), ("tool", "S0363")])
    def test_the_node_and_its_links_do_not_depend_on_the_galaxy(self, kind, attack_id):
        build = {"malware": "create_malware_attribute", "tool": "create_tool_attribute"}[kind]
        new = _stored(getattr(_writer(SOFTWARE), build)(_text_item(kind, attack_id)))
        old = _stored(getattr(_writer(None), build)(_text_item(kind, attack_id)))
        assert _galaxy_tags(new) != _galaxy_tags(old)
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        new_item, new_rels = syncer.parse_attribute(copy.deepcopy(new), EVENT)
        old_item, old_rels = syncer.parse_attribute(copy.deepcopy(old), EVENT)
        assert new_item == old_item and new_rels == old_rels
        assert new_item["type"] == kind  # from the attribute's type and value, not from a galaxy tag
        # The names the tags give (read for indicator attributes only): ``mitre-malware="..."`` repeated the
        # community tag's name, ``mitre-software="..."`` is not read as a malware name (it holds tools too).
        assert set(syncer._extract_malware_from_tags(new["Tag"])) == set(syncer._extract_malware_from_tags(old["Tag"]))
        assert syncer._extract_sector_from_tags(new["Tag"]) is None
