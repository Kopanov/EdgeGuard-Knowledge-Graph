"""The revoked ATT&CK id map (2026-10): ``scripts/build_attack_revoked_ids.py`` and ``src/attack_revoked.py``.

ATT&CK keeps a replaced object with ``revoked: true`` and a ``revoked-by`` relationship to its
successor. The builder reads the MITRE galaxies of MISP (each cluster's ``revoked-by`` relation
names the successor's cluster uuid; the ATT&CK id is the suffix of the cluster value) and writes
``src/reference/attack_revoked_ids.json``; the loader reads it once per process for every place a
feed names a technique by id. Fixtures here are galaxy clusters in the shape of the captured
``galaxy_clusters/restSearch`` answers (``Core-Ideas_CTI/data/open/raw/misp_galaxy_*``).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import random
import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import attack_revoked  # noqa: E402

MAP = _SRC / "reference" / "attack_revoked_ids.json"
MITRE_NOTICE = (
    "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
)


@pytest.fixture(scope="module")
def builder():
    spec = importlib.util.spec_from_file_location(
        "build_attack_revoked_ids", _ROOT / "scripts" / "build_attack_revoked_ids.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _cluster(uuid, value, revoked_by=(), version="41", external_id=None):
    """One galaxy cluster as MISP serves it (only the fields the builder reads, plus a relation of
    another type so the filter on ``revoked-by`` is exercised)."""
    elements = []
    suffix = value.rsplit(" - ", 1)[-1] if " - " in value else None
    if external_id or suffix:
        elements.append({"key": "external_id", "value": external_id or suffix})
    relations = [
        {"referenced_galaxy_cluster_type": "revoked-by", "referenced_galaxy_cluster_uuid": u} for u in revoked_by
    ]
    relations.append({"referenced_galaxy_cluster_type": "related-to", "referenced_galaxy_cluster_uuid": "other"})
    return {
        "uuid": uuid,
        "value": value,
        "version": version,
        "GalaxyElement": elements,
        "GalaxyClusterRelation": relations,
    }


def _capture(galaxy, clusters, captured_at="2026-10-13T00:34:24+02:00"):
    """A capture file as written into ``Core-Ideas_CTI/data/open/raw``."""
    return {
        "captured_at": captured_at,
        "source": "misp-galaxy",
        "request": {
            "method": "POST",
            "path": "/galaxy_clusters/restSearch",
            "misp_version": "2.5.45",
            "galaxy": {"type": galaxy, "name": f"{galaxy} name", "version": "9"},
        },
        "payload": {"response": [{"GalaxyCluster": c} for c in clusters]},
    }


def _write_raw_dir(root: Path, by_galaxy, date="20261013"):
    root.mkdir(parents=True, exist_ok=True)
    for galaxy, clusters in by_galaxy.items():
        (root / f"misp_galaxy_{galaxy}_{date}.json").write_text(json.dumps(_capture(galaxy, clusters)))
    return root


REAL_SHAPED = {
    "mitre-attack-pattern": [
        _cluster("u-t1086", "PowerShell - T1086", revoked_by=["u-t1059-001"]),
        _cluster("u-t1059-001", "PowerShell - T1059.001"),
        _cluster("u-t1073", "DLL Side-Loading - T1073", revoked_by=["u-t1574-002"]),
        _cluster("u-t1574-002", "DLL Side-Loading - T1574.002", revoked_by=["u-t1574-001"]),
        _cluster("u-t1574-001", "DLL - T1574.001"),
        _cluster("u-t1171", "LLMNR/NBT-NS Poisoning and Relay - T1171", revoked_by=["u-t1557-001"]),
        # MISP keeps the older copy of a renamed cluster under the same uuid
        _cluster("u-t1557-001", "LLMNR/NBT-NS Poisoning and SMB Relay - T1557.001", version="35"),
        _cluster("u-t1557-001", "Name Resolution Poisoning and SMB Relay - T1557.001", version="41"),
        _cluster("u-ta0005", "Stealth - TA0005"),
    ],
    "mitre-intrusion-set": [
        _cluster("u-g0118", "UNC2452 - G0118", revoked_by=["u-g0016"]),
        _cluster("u-g0016", "APT29 - G0016"),
    ],
    "mitre-malware": [
        _cluster("u-s0209", "Darkmoon - S0209", revoked_by=["u-s0012"]),
        _cluster("u-s0012", "PoisonIvy - S0012"),
        _cluster("u-s9000", "Ngrok - S9000", revoked_by=["u-s0508"]),
    ],
    "mitre-tool": [_cluster("u-s0508", "ngrok - S0508")],
    # ICS groups carry no ATT&CK id in the value today
    "mitre-ics-groups": [_cluster("u-ics", "Sandworm Team")],
}


def _all_clusters(by_galaxy=REAL_SHAPED):
    return [c for clusters in by_galaxy.values() for c in clusters]


# --------------------------------------------------------------------------- builder
class TestBuildMap:
    def test_revoked_ids_by_kind_with_names(self, builder):
        built = builder.build_map(_all_clusters())
        assert built["techniques"]["T1086"] == {
            "name": "PowerShell",
            "successor": "T1059.001",
            "successor_name": "PowerShell",
        }
        assert built["groups"] == {"G0118": {"name": "UNC2452", "successor": "G0016", "successor_name": "APT29"}}
        assert built["software"] == {
            "S0209": {"name": "Darkmoon", "successor": "S0012", "successor_name": "PoisonIvy"},
            # malware revoked by a tool: both software (S…), so translatable
            "S9000": {"name": "Ngrok", "successor": "S0508", "successor_name": "ngrok"},
        }
        assert built["excluded"] == [] and built["notes"] == []
        assert built["counts"] == {"techniques": 4, "groups": 1, "software": 2, "via_chain": 1, "excluded": 0}

    def test_a_chain_is_followed_to_its_last_successor(self, builder):
        built = builder.build_map(_all_clusters())
        assert built["techniques"]["T1073"] == {
            "name": "DLL Side-Loading",
            "successor": "T1574.001",
            "successor_name": "DLL",
            "via": ["T1574.002"],
        }
        assert built["techniques"]["T1574.002"] == {
            "name": "DLL Side-Loading",
            "successor": "T1574.001",
            "successor_name": "DLL",
        }
        longer = [
            _cluster("a", "A - T0001", revoked_by=["b"]),
            _cluster("b", "B - T0002", revoked_by=["c"]),
            _cluster("c", "C - T0003", revoked_by=["d"]),
            _cluster("d", "D - T0004"),
        ]
        techniques = builder.build_map(longer)["techniques"]
        assert techniques["T0001"]["via"] == ["T0002", "T0003"] and techniques["T0001"]["successor"] == "T0004"
        assert {t: e["successor"] for t, e in techniques.items()} == {
            "T0001": "T0004",
            "T0002": "T0004",
            "T0003": "T0004",
        }

    def test_the_current_name_of_a_renamed_successor(self, builder):
        clusters = _all_clusters()
        for order in (clusters, list(reversed(clusters))):
            entry = builder.build_map(order)["techniques"]["T1171"]
            assert entry["successor"] == "T1557.001"
            assert entry["successor_name"] == "Name Resolution Poisoning and SMB Relay", "highest version wins"

    @pytest.mark.parametrize(
        "clusters, excluded_ids",
        [
            # a two-step loop, reached from a third id
            (
                [
                    _cluster("a", "A - T0001", revoked_by=["b"]),
                    _cluster("b", "B - T0002", revoked_by=["a"]),
                    _cluster("x", "X - T0003", revoked_by=["a"]),
                ],
                {"T0001", "T0002", "T0003"},
            ),
            ([_cluster("a", "A - T0001", revoked_by=["a"])], {"T0001"}),  # revoked by itself
        ],
    )
    def test_a_loop_is_detected_and_excluded(self, builder, clusters, excluded_ids):
        built = builder.build_map(clusters)
        assert built["techniques"] == {}
        assert {e["id"] for e in built["excluded"]} == excluded_ids
        assert all("loops" in e["reason"] for e in built["excluded"]), built["excluded"]

    @pytest.mark.parametrize(
        "clusters, reason",
        [
            ([_cluster("a", "A - T0001", revoked_by=["missing"])], "not in the inputs"),
            (
                [_cluster("a", "A - T0001", revoked_by=["g"]), _cluster("g", "G - G0001")],
                "not of the same kind",
            ),
            (
                [_cluster("a", "A - T0001", revoked_by=["b"]), _cluster("b", "B - T0002"), _cluster("c", "C - T0001")],
                "not revoked carries the same id",
            ),
            (
                [
                    _cluster("a", "A - T0001", revoked_by=["b", "c"]),
                    _cluster("b", "B - T0002"),
                    _cluster("c", "C - T0003"),
                ],
                "revoked by 2 clusters",
            ),
            ([_cluster("a", "A - G0001", revoked_by=["b"]), _cluster("b", "No id here")], "has no ATT&CK id"),
        ],
    )
    def test_ids_that_cannot_be_translated_are_listed_not_mapped(self, builder, clusters, reason):
        built = builder.build_map(clusters)
        assert built["techniques"] == {} and built["groups"] == {}
        assert len(built["excluded"]) == 1 and reason in built["excluded"][0]["reason"], built["excluded"]

    def test_ids_come_from_the_value_suffix(self, builder):
        clusters = [
            _cluster("a", "Valid Accounts - Cloud Accounts - T1078.004", revoked_by=["b"]),
            _cluster("b", "Cloud Accounts - T1078.005"),
            _cluster("t", "Defense Evasion - TA0005", revoked_by=["u"]),  # tactics are not translated
            _cluster("u", "Stealth - TA0099"),
            _cluster("i", "Sandworm Team", revoked_by=["b"]),  # no id in the value
        ]
        built = builder.build_map(clusters)
        assert built["techniques"] == {
            "T1078.004": {
                "name": "Valid Accounts - Cloud Accounts",
                "successor": "T1078.005",
                "successor_name": "Cloud Accounts",
            }
        }
        assert any("no ATT&CK id" in note for note in built["notes"])

    def test_a_cluster_with_two_ids_is_an_error(self, builder):
        with pytest.raises(builder.BuildError, match="two ATT&CK ids"):
            builder.build_map([_cluster("a", "A - T0001"), _cluster("a", "A - T0002")])

    def test_output_does_not_depend_on_cluster_order(self, builder):
        clusters = _all_clusters()
        first = builder.render(builder.build_map(clusters))
        for seed in range(5):
            shuffled = list(clusters)
            random.Random(seed).shuffle(shuffled)
            assert builder.render(builder.build_map(shuffled)) == first


class TestInputsAndDocument:
    def test_newest_capture_per_galaxy_and_the_ics_ones(self, builder, tmp_path):
        raw = _write_raw_dir(tmp_path / "open" / "raw", REAL_SHAPED)
        old = _capture("mitre-tool", [])
        (raw / "misp_galaxy_mitre-tool_20250101.json").write_text(json.dumps(old))
        (raw / "misp_galaxy_ransomware_20261013.json").write_text("{}")  # not a MITRE galaxy: never read
        names = [p.name for p in builder.find_inputs(raw)]
        assert names == [
            "misp_galaxy_mitre-attack-pattern_20261013.json",
            "misp_galaxy_mitre-ics-groups_20261013.json",
            "misp_galaxy_mitre-intrusion-set_20261013.json",
            "misp_galaxy_mitre-malware_20261013.json",
            "misp_galaxy_mitre-tool_20261013.json",
        ]

    def test_a_required_galaxy_missing_is_an_error(self, builder, tmp_path):
        raw = _write_raw_dir(tmp_path / "raw", {k: v for k, v in REAL_SHAPED.items() if k != "mitre-malware"})
        with pytest.raises(builder.BuildError, match="mitre-malware"):
            builder.find_inputs(raw)

    def test_a_restricted_folder_is_refused(self, builder, tmp_path):
        raw = _write_raw_dir(tmp_path / "data" / "restricted" / "raw", REAL_SHAPED)
        with pytest.raises(builder.BuildError, match="restricted"):
            builder.find_inputs(raw)
        assert builder.main([str(raw), "--output", str(tmp_path / "out.json")]) == 1
        assert not (tmp_path / "out.json").exists()

    def test_document_metadata_and_byte_identical_rebuild(self, builder, tmp_path):
        raw = _write_raw_dir(tmp_path / "raw", REAL_SHAPED)
        paths = builder.find_inputs(raw)
        doc = builder.build_document(paths, "2026.10.15", "2026-10-15T08:00:00Z")
        assert doc["version"] == "2026.10.15" and doc["generated_at"] == "2026-10-15T08:00:00Z"
        assert doc["notices"]["mitre_attack"] == MITRE_NOTICE
        assert "CC0 1.0" in doc["notices"]["misp_galaxy"]
        for record, path in zip(doc["inputs"], sorted(paths, key=lambda p: p.name), strict=True):
            assert record["file"] == path.name and "/" not in record["file"], "no local path in the map"
            assert record["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert sum(r["revoked_clusters"] for r in doc["inputs"]) == 7
        again = builder.build_document(list(reversed(paths)), "2026.10.15", "2026-10-15T08:00:00Z")
        assert builder.render(again) == builder.render(doc)

    def test_main_writes_a_map_the_loader_accepts(self, builder, tmp_path):
        raw = _write_raw_dir(tmp_path / "raw", REAL_SHAPED)
        out = tmp_path / "reference" / "attack_revoked_ids.json"
        argv = [str(raw), "--output", str(out), "--version", "2026.10.15", "--generated-at", "2026-10-15T08:00:00Z"]
        assert builder.main(argv) == 0
        first = out.read_bytes()
        assert builder.main(argv) == 0 and out.read_bytes() == first, "same inputs and arguments, same bytes"
        loaded = attack_revoked.load_revoked_ids(out)
        assert loaded.loaded and loaded.version == "2026.10.15"
        assert loaded.techniques == {
            "T1086": "T1059.001",
            "T1073": "T1574.001",
            "T1574.002": "T1574.001",
            "T1171": "T1557.001",
        }
        assert loaded.groups == {"G0118": "G0016"} and loaded.group_names() == ["UNC2452"]

    def test_calver_has_no_leading_zeros(self, builder):
        from datetime import date

        assert builder.calver(date(2026, 10, 15)) == "2026.10.15"
        assert builder.calver(date(2026, 11, 5)) == "2026.11.5"


# --------------------------------------------------------------------------- committed map
class TestCommittedMap:
    def test_it_loads_with_the_known_revocations(self):
        revoked = attack_revoked.load_revoked_ids()
        assert revoked.loaded, revoked.problem
        assert revoked.path == str(MAP)
        assert revoked.techniques["T1086"] == "T1059.001"  # PowerShell, cited by OTX pulses
        assert revoked.techniques["T1073"] == "T1574.001"  # through T1574.002
        assert revoked.techniques["T1562.001"] == "T1685"
        assert revoked.groups["G0118"] == "G0016"  # UNC2452 -> APT29
        assert revoked.groups["G0057"] == "G0049"  # APT34 -> OilRig
        assert revoked.software["S0209"] == "S0012"  # Darkmoon -> PoisonIvy
        assert {"UNC2452", "APT34", "Charming Kitten", "MONSOON", "Dragonfly 2.0", "Stolen Pencil"} <= set(
            revoked.group_names()
        )

    def test_metadata_and_counts(self):
        doc = json.loads(MAP.read_text(encoding="utf-8"))
        assert re.fullmatch(r"\d{4}\.\d{1,2}\.\d{1,2}", doc["version"])
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", doc["generated_at"])
        assert doc["notices"]["mitre_attack"] == MITRE_NOTICE and "CC0" in doc["notices"]["misp_galaxy"]
        galaxies = {i["galaxy"] for i in doc["inputs"]}
        assert {"mitre-attack-pattern", "mitre-intrusion-set", "mitre-malware", "mitre-tool"} <= galaxies
        assert all(re.fullmatch(r"[0-9a-f]{64}", i["sha256"]) for i in doc["inputs"])
        for section in ("techniques", "groups", "software"):
            assert doc["counts"][section] == len(doc[section]) > 0
            assert list(doc[section]) == sorted(doc[section]), "entries are sorted"
            assert not set(e["successor"] for e in doc[section].values()) & set(doc[section]), "chains resolved"

    def test_the_file_is_what_the_builder_renders(self, builder):
        text = MAP.read_text(encoding="utf-8")
        assert builder.render(json.loads(text)) == text


# --------------------------------------------------------------------------- loader
def _write_map(path: Path, document) -> Path:
    path.write_text(document if isinstance(document, str) else json.dumps(document), encoding="utf-8")
    return path


def _valid(**sections):
    doc = {"version": "2026.10.15", "techniques": {}, "groups": {}, "software": {}}
    doc.update(sections)
    return doc


class TestLoader:
    def test_a_missing_file_warns_once_and_translates_nothing(self, tmp_path, caplog):
        path = tmp_path / "attack_revoked_ids.json"
        with caplog.at_level(logging.WARNING, logger="attack_revoked"):
            first = attack_revoked.load_revoked_ids(path)
            second = attack_revoked.load_revoked_ids(path)
            successors = attack_revoked.technique_successors(path)
        assert first is second, "read once per process"
        assert not first.loaded and first.problem == "file not found"
        assert first.technique_successor("T1086") is None and first.translate_technique("T1086") == "T1086"
        assert successors == {} and first.group_names() == []
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1 and "not translated" in warnings[0].getMessage()

    @pytest.mark.parametrize(
        "document, problem",
        [
            ("{not json", "JSONDecodeError"),
            ("[]", "not a JSON object"),
            ({"techniques": {}, "groups": {}, "software": {}}, "no 'version'"),
            ({"version": "1", "groups": {}, "software": {}}, "'techniques' is missing"),
            (_valid(techniques={"X1086": {"successor": "T1059.001"}}), "malformed id"),
            (_valid(techniques={"T1086": {"successor": "T10"}}), "malformed successor"),
            (_valid(techniques={"T1086": "T1059.001"}), "malformed successor"),
            (_valid(groups={"G0118": {"successor": "T1059"}}), "malformed successor"),
            (_valid(techniques={"T1086": {"successor": "T1086"}}), "its own successor"),
            (
                _valid(techniques={"T0001": {"successor": "T0002"}, "T0002": {"successor": "T0003"}}),
                "unresolved chain",
            ),
        ],
    )
    def test_an_invalid_file_warns_and_translates_nothing(self, tmp_path, caplog, document, problem):
        path = _write_map(tmp_path / "attack_revoked_ids.json", document)
        with caplog.at_level(logging.WARNING, logger="attack_revoked"):
            revoked = attack_revoked.load_revoked_ids(path)
        assert not revoked.loaded and problem in revoked.problem, revoked.problem
        assert revoked.techniques == {} and attack_revoked.technique_successors(path) == {}
        assert sum(1 for r in caplog.records if r.levelno == logging.WARNING) == 1

    def test_lookups_ignore_case_and_surrounding_space(self, tmp_path):
        path = _write_map(
            tmp_path / "m.json", _valid(techniques={"T1086": {"name": "PowerShell", "successor": "T1059.001"}})
        )
        revoked = attack_revoked.load_revoked_ids(path)
        assert revoked.technique_successor(" t1086 ") == "T1059.001"
        assert revoked.translate_technique("t1086") == "T1059.001"
        assert revoked.translate_technique("T1059") == "T1059" and revoked.technique_successor(None) is None

    def test_group_names_leave_out_a_name_a_live_group_bears(self, tmp_path):
        groups = {
            "G0118": {"name": "UNC2452", "successor": "G0016", "successor_name": "APT29"},
            "G9999": {"name": "apt29", "successor": "G0016", "successor_name": "APT29"},
        }
        revoked = attack_revoked.load_revoked_ids(_write_map(tmp_path / "m.json", _valid(groups=groups)))
        assert revoked.group_names() == ["UNC2452"]

    def test_reset_cache_reads_the_file_again(self, tmp_path):
        path = _write_map(tmp_path / "m.json", _valid())
        first = attack_revoked.load_revoked_ids(path)
        _write_map(path, _valid(techniques={"T1086": {"successor": "T1059.001"}}))
        assert attack_revoked.load_revoked_ids(path) is first
        attack_revoked.reset_cache()
        assert attack_revoked.load_revoked_ids(path).techniques == {"T1086": "T1059.001"}
