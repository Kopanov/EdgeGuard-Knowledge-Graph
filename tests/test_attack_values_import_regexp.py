"""ATT&CK values that MISP's default Import Regexp rules leave unchanged (2026-10-20).

MISP applies its Import Regexp rules to the value of every attribute it stores. The default rules
(the rows of MISP's ``regexp`` table, ``MISP_DEFAULT_IMPORT_REGEXP`` below) normalise Windows paths
in file-name indicators, and most of them begin with any character, a colon and any character
(``/.:.Windows./i`` → ``%WINDIR%\\``). MISPWriter wrote each ATT&CK technique, tactic and tool as
``<id>: <name>``, so MISP stored ``T1059.003: Windows Command Shell`` as
``T1059.00%WINDIR%\\Command Shell``. On the hosted run of 2026-10-20 nine entries (T1059.003, T1047,
T1021.006, T1543.003, T1222.001, T1546.003, T1555.004, T1686.003, S0005) became Technique nodes with a
broken id and no name, or ``unknown`` Indicator nodes, and the links that cite them were lost.

The value is now ``<id> - <name>``. The sync reads both forms through one helper
(``attack_values.parse_attack_value``) and skips, with an ``[ATTACK-VALUE]`` warning and a count, a
value that starts like an ATT&CK id but holds no valid one. The rewritten values below are the ones
MISP returned on the hosted instance (captured 2026-10-09).
"""

from __future__ import annotations

import logging
import re
import sys
from copy import deepcopy
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from collectors import misp_writer as mw  # noqa: E402
from collectors import mitre_collector as mc  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

# --------------------------------------------------------------------------- MISP's default rules
# MISP's default Import Regexp list: the rows of the ``regexp`` table that MISP's INSTALL/MYSQL.sql
# inserts (identical on the 2.4 and 2.5 branches), in id order, every row of type ``ALL``. SQL and
# PHP escaping resolved: ``\\`` in a pattern is one literal backslash, and a replacement written
# ``%WINDIR%\\\\`` in the SQL stores ``%WINDIR%\`` in the value. ``Regexp::replaceSpecific`` applies
# a rule with a replacement with ``preg_replace`` (every match) and refuses the value when a rule
# with an empty replacement matches it. Patterns are case-insensitive (``/i``).
MISP_DEFAULT_IMPORT_REGEXP = (
    (r".:.ProgramData.", "%ALLUSERSPROFILE%\\"),
    (r".:.Documents and Settings.All Users.", "%ALLUSERSPROFILE%\\"),
    (r".:.Program Files.Common Files.", "%COMMONPROGRAMFILES%\\"),
    (r".:.Program Files (x86).Common Files.", "%COMMONPROGRAMFILES(x86)%\\"),
    (r".:.Users\\(.*?)\\AppData.Local.Temp.", "%TEMP%\\"),
    (r".:.ProgramData.", "%PROGRAMDATA%\\"),
    (r".:.Program Files.", "%PROGRAMFILES%\\"),
    (r".:.Program Files (x86).", "%PROGRAMFILES(X86)%\\"),
    (r".:.Users.Public.", "%PUBLIC%\\"),
    (r".:.Documents and Settings\\(.*?)\\Local Settings.Temp.", "%TEMP%\\"),
    (r".:.Users\\(.*?)\\AppData.Local.Temp.", "%TEMP%\\"),
    (r".:.Users\\(.*?)\\AppData.Local.", "%LOCALAPPDATA%\\"),
    (r".:.Users\\(.*?)\\AppData.Roaming.", "%APPDATA%\\"),
    (r".:.Users\\(.*?)\\Application Data.", "%APPDATA%\\"),
    (r".:.Windows\\(.*?)\\Application Data.", "%APPDATA%\\"),
    (r".:.Users\\(.*?)\\", "%USERPROFILE%\\"),
    (r".:.DOCUME~1.\\(.*?)\\", "%USERPROFILE%\\"),
    (r".:.Documents and Settings\\(.*?)\\", "%USERPROFILE%\\"),
    (r".:.Windows.", "%WINDIR%\\"),
    (r".:.Windows.", "%WINDIR%\\"),
    (r".REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{9}){1}(-[0-9]{10}){1}-[0-9]{9}-[0-9]{4}", "HKCU"),
    (r".REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){2}-[0-9]{9}-[0-9]{4}", "HKCU"),
    (r".REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){3}-[0-9]{4}", "HKCU"),
    (r".REGISTRY.MACHINE.", "HKLM\\"),
    (r".Registry.Machine.", "HKLM\\"),
    (r"%USERPROFILE%.Application Data.Microsoft.UProof", ""),
    (r"%USERPROFILE%.Local Settings.History", ""),
    (r"%APPDATA%.Microsoft.UProof", ""),
    (r"%LOCALAPPDATA%.Microsoft.Windows.Temporary Internet Files", ""),
)
_COMPILED_RULES = tuple((re.compile(p, re.IGNORECASE), r) for p, r in MISP_DEFAULT_IMPORT_REGEXP)


def misp_import(value: str) -> Optional[str]:
    """``value`` as MISP stores it under its default Import Regexp rules; None when a rule refuses it."""
    for rule, replacement in _COMPILED_RULES:
        if replacement:
            value = rule.sub(lambda _m, r=replacement: r, value)
        elif rule.search(value):
            return None
    return value


# The rewritten values MISP returned on the hosted instance (captured 2026-10-09), from the values
# MISPWriter wrote as ``<id>: <name>`` (T1028, T1077 and T1084 are techniques ATT&CK revoked, which the
# MITRE collector still wrote then).
MISP_REWRITTEN = {
    "T1059.003: Windows Command Shell": "T1059.00%WINDIR%\\Command Shell",
    "T1047: Windows Management Instrumentation": "T104%WINDIR%\\Management Instrumentation",
    "T1021.006: Windows Remote Management": "T1021.00%WINDIR%\\Remote Management",
    "T1543.003: Windows Service": "T1543.00%WINDIR%\\Service",
    "T1222.001: Windows Permissions": "T1222.00%WINDIR%\\Permissions",
    "T1546.003: Windows Management Instrumentation Event Subscription": (
        "T1546.00%WINDIR%\\Management Instrumentation Event Subscription"
    ),
    "T1555.004: Windows Credential Manager": "T1555.00%WINDIR%\\Credential Manager",
    "T1686.003: Windows Host Firewall": "T1686.00%WINDIR%\\Host Firewall",
    "S0005: Windows Credential Editor": "S000%WINDIR%\\Credential Editor",
    "T1028: Windows Remote Management": "T102%WINDIR%\\Remote Management",
    "T1077: Windows Admin Shares": "T107%WINDIR%\\Admin Shares",
    "T1084: Windows Management Instrumentation Event Subscription": (
        "T108%WINDIR%\\Management Instrumentation Event Subscription"
    ),
}


class TestTheRuleListReproducesMisp:
    @pytest.mark.parametrize("written, stored", sorted(MISP_REWRITTEN.items()))
    def test_the_rules_rewrite_the_old_values_as_misp_did(self, written, stored):
        assert misp_import(written) == stored

    def test_the_rules_still_normalise_a_windows_path(self):
        assert misp_import("C:\\Windows\\System32\\evil.exe") == "%WINDIR%\\System32\\evil.exe"
        assert misp_import("C:\\Program Files\\x\\y.dll") == "%PROGRAMFILES%\\x\\y.dll"


# --------------------------------------------------------------------------- a bundle with "Windows ..." names
_CREATED = "2017-05-31T21:31:00.645Z"
_MODIFIED = "2025-10-24T17:48:25.234Z"


def _ext(mitre_id: str, kind: str) -> List[Dict]:
    return [
        {
            "source_name": "mitre-attack",
            "external_id": mitre_id,
            "url": f"https://attack.mitre.org/{kind}/{mitre_id.replace('.', '/')}",
        }
    ]


def _sdo(stix_type: str, n: int, name: str, domain: str = "enterprise-attack", **fields) -> Dict:
    obj = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": f"{stix_type}--00000000-0000-4000-8000-{n:012d}",
        "created": _CREATED,
        "modified": _MODIFIED,
        "name": name,
        "description": f"{name} description.",
        "x_mitre_domains": [domain],
    }
    obj.update(fields)
    return obj


def _technique(n: int, mitre_id: str, name: str, phase: str, kill_chain: str = "mitre-attack", **kw) -> Dict:
    return _sdo(
        "attack-pattern",
        n,
        name,
        external_references=_ext(mitre_id, "techniques"),
        kill_chain_phases=[{"kill_chain_name": kill_chain, "phase_name": phase}],
        x_mitre_is_subtechnique="." in mitre_id,
        x_mitre_platforms=["Windows"],
        **kw,
    )


def _tactic(n: int, mitre_id: str, name: str, shortname: str, **kw) -> Dict:
    return _sdo(
        "x-mitre-tactic", n, name, external_references=_ext(mitre_id, "tactics"), x_mitre_shortname=shortname, **kw
    )


def _rel(n: int, src: Dict, tgt: Dict, rel_type: str = "uses") -> Dict:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--00000000-0000-4000-9000-{n:012d}",
        "created": _CREATED,
        "modified": _MODIFIED,
        "relationship_type": rel_type,
        "source_ref": src["id"],
        "target_ref": tgt["id"],
    }


# Enterprise: the nine entries of the hosted run plus their parents, two tactics, a group, a malware
# and the tool S0005; names as ATT&CK v20 gives them.
_WINDOWS_TECHNIQUES = (
    ("T1059.003", "Windows Command Shell", "execution"),
    ("T1047", "Windows Management Instrumentation", "execution"),
    ("T1021.006", "Windows Remote Management", "lateral-movement"),
    ("T1543.003", "Windows Service", "persistence"),
    ("T1222.001", "Windows Permissions", "stealth"),
    ("T1546.003", "Windows Management Instrumentation Event Subscription", "persistence"),
    ("T1555.004", "Windows Credential Manager", "credential-access"),
    ("T1686.003", "Windows Host Firewall", "defense-impairment"),
)
_PARENTS = (
    ("T1059", "Command and Scripting Interpreter", "execution"),
    ("T1021", "Remote Services", "lateral-movement"),
    ("T1686", "Disable or Modify System Firewall", "defense-impairment"),
)


def _enterprise_bundle() -> Dict:
    techniques = [_technique(i, *t) for i, t in enumerate(_WINDOWS_TECHNIQUES + _PARENTS, start=1)]
    tactics = [
        _tactic(101, "TA0002", "Execution", "execution"),
        _tactic(102, "TA0006", "Credential Access", "credential-access"),
    ]
    group = _sdo(
        "intrusion-set", 201, "APT29", aliases=["APT29", "Cozy Bear"], external_references=_ext("G0016", "groups")
    )
    tool = _sdo(
        "tool", 301, "Windows Credential Editor", labels=["tool"], external_references=_ext("S0005", "software")
    )
    malware = _sdo("malware", 302, "WinMM", labels=["malware"], external_references=_ext("S0059", "software"))
    rels = [
        _rel(1, group, techniques[0]),
        _rel(2, group, tool),
        _rel(3, tool, techniques[6]),
        _rel(4, malware, techniques[1]),
    ]
    return {
        "type": "bundle",
        "id": "bundle--0a000000-0000-4000-8000-000000000001",
        "objects": [*techniques, *tactics, group, tool, malware, *rels],
    }


def _ics_bundle() -> Dict:
    objects = [
        _technique(
            401, "T0807", "Command-Line Interface", "execution-ics", "mitre-ics-attack", x_mitre_domains=["ics-attack"]
        ),
        _technique(
            402, "T0871", "Execution through API", "execution-ics", "mitre-ics-attack", x_mitre_domains=["ics-attack"]
        ),
        _tactic(501, "TA0104", "Execution", "execution-ics", x_mitre_domains=["ics-attack"]),
    ]
    return {"type": "bundle", "id": "bundle--0a000000-0000-4000-8000-000000000002", "objects": objects}


def _writer() -> MISPWriter:
    return MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)


def _pushed_attributes(monkeypatch) -> List[Dict]:
    """Every attribute MISPWriter builds for the items MITRECollector collects from both bundles."""
    pushed: List[Dict] = []
    writer = _writer()
    monkeypatch.setattr(mw, "MISP_PREFETCH_EXISTING_ATTRS", False)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", False)
    monkeypatch.setattr(writer, "_get_or_create_event", lambda *a, **k: "42")

    def push_batch(event_id, attributes):
        pushed.extend(attributes)
        return len(attributes), 0

    monkeypatch.setattr(writer, "_push_batch", push_batch)
    collector = mc.MITRECollector(misp_writer=writer)
    breaker = MagicMock()
    breaker.can_execute.return_value = True
    monkeypatch.setattr(mc, "MITRE_CIRCUIT_BREAKER", breaker)
    monkeypatch.setattr(mc, "MITRE_MAX_RELATIONSHIPS", 0)
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", True)
    monkeypatch.setattr(mc, "update_source_incremental", lambda *a, **k: None)
    monkeypatch.setattr(mc, "get_source_incremental", lambda *a, **k: {})
    monkeypatch.setattr(mc.MITRE_RATE_LIMITER, "wait_if_needed", lambda: None)

    def download(etag=None, url=None):
        return deepcopy(_ics_bundle() if url == collector.ics_attack_url else _enterprise_bundle()), None

    monkeypatch.setattr(collector, "_download_stix_bundle", download)
    status = collector.collect(push_to_misp=True, baseline=True)
    assert status["success"] is True, status
    return pushed


def _attack_text_values(attributes: List[Dict]) -> Dict[str, str]:
    """``mitre id → value`` of the ``text`` attributes (techniques, tactics, tools)."""
    out = {}
    for attr in attributes:
        if attr["type"] == "text":
            out[attr["value"].split(" ", 1)[0].rstrip(":")] = attr["value"]
    return out


class TestTheWriterValues:
    def test_every_attack_value_is_id_dash_name_without_a_colon(self, monkeypatch):
        values = _attack_text_values(_pushed_attributes(monkeypatch))
        expected = {
            **{mitre_id: f"{mitre_id} - {name}" for mitre_id, name, _ in _WINDOWS_TECHNIQUES + _PARENTS},
            "TA0002": "TA0002 - Execution",
            "TA0006": "TA0006 - Credential Access",
            "S0005": "S0005 - Windows Credential Editor",
            "T0807": "T0807 - Command-Line Interface",
            "T0871": "T0871 - Execution through API",
            "TA0104": "TA0104 - Execution",
        }
        assert values == expected
        assert not [v for v in values.values() if ":" in v]

    @pytest.mark.parametrize(
        "create, item",
        [
            ("create_technique_attribute", {"mitre_id": "T1059.003", "name": "Windows Command Shell"}),
            ("create_tactic_attribute", {"mitre_id": "TA0002", "name": "Execution", "shortname": "execution"}),
            ("create_tool_attribute", {"mitre_id": "S0005", "name": "Windows Credential Editor"}),
            (
                "create_technique_attribute",
                {"mitre_id": "T0807", "name": "Command-Line Interface", "attack_domain": "ics"},
            ),
            ("create_tactic_attribute", {"mitre_id": "TA0104", "name": "Execution", "attack_domain": "ics"}),
        ],
    )
    def test_each_attack_writer_writes_no_colon(self, create, item):
        attr = getattr(_writer(), create)({**item, "tag": "mitre_attck", "zone": ["global"]})
        assert attr["type"] == "text"
        assert attr["value"] == f"{item['mitre_id']} - {item['name']}"
        assert ":" not in attr["value"]

    def test_misp_default_rules_leave_every_value_unchanged(self, monkeypatch):
        attributes = _pushed_attributes(monkeypatch)
        # 13 techniques (2 of them ICS), 3 tactics (1 ICS), the tool, the group and the malware
        assert len(attributes) == 19
        assert {a["type"] for a in attributes} == {"text", "threat-actor", "malware-type"}
        changed = {a["value"]: misp_import(a["value"]) for a in attributes if misp_import(a["value"]) != a["value"]}
        assert changed == {}


# --------------------------------------------------------------------------- the sync reads both forms
_EVENT = {"id": "33", "info": "EdgeGuard-mitre_attck-2026-10-20", "date": "2026-10-20", "Tag": []}


def _text_attr(value: str, tags=("source:MITRE-ATT&CK", "tlp:clear")) -> Dict:
    return {
        "type": "text",
        "value": value,
        "uuid": "20000000-0000-4000-8000-000000000001",
        "comment": "",
        "Tag": [{"name": t} for t in tags],
    }


@pytest.fixture
def syncer() -> MISPToNeo4jSync:
    return MISPToNeo4jSync(neo4j_client=MagicMock())


class TestTheSyncReadsBothForms:
    @pytest.mark.parametrize(
        "create, item, kind",
        [
            ("create_technique_attribute", {"mitre_id": "T1059.003", "name": "Windows Command Shell"}, "technique"),
            (
                "create_tactic_attribute",
                {"mitre_id": "TA0002", "name": "Execution", "shortname": "execution"},
                "tactic",
            ),
            ("create_tool_attribute", {"mitre_id": "S0005", "name": "Windows Credential Editor"}, "tool"),
            ("create_technique_attribute", {"mitre_id": "T0807", "name": "Command-Line Interface"}, "technique"),
        ],
    )
    def test_writer_to_sync_round_trip_keeps_id_and_name(self, syncer, create, item, kind):
        attr = getattr(_writer(), create)({**item, "tag": "mitre_attck", "zone": ["global"]})
        attr["uuid"] = "20000000-0000-4000-8000-000000000002"
        attr["value"] = misp_import(attr["value"])  # what MISP stores and the sync reads
        parsed, _rels = syncer.parse_attribute(attr, _EVENT)
        assert parsed is not None
        assert (parsed["type"], parsed["mitre_id"], parsed["name"]) == (kind, item["mitre_id"], item["name"])

    @pytest.mark.parametrize(
        "value, kind, mitre_id, name",
        [
            ("T1059.003: Windows Command Shell", "technique", "T1059.003", "Windows Command Shell"),
            ("T1059.003 - Windows Command Shell", "technique", "T1059.003", "Windows Command Shell"),
            ("TA0002: Execution", "tactic", "TA0002", "Execution"),
            ("TA0002 - Execution", "tactic", "TA0002", "Execution"),
            ("S0002: Mimikatz", "tool", "S0002", "Mimikatz"),
            ("S0002 - Mimikatz", "tool", "S0002", "Mimikatz"),
            ("T1218.011 - Rundll32", "technique", "T1218.011", "Rundll32"),
            ("T1003 - OS Credential Dumping - Extra", "technique", "T1003", "OS Credential Dumping - Extra"),
        ],
    )
    def test_both_forms_parse_to_the_same_item(self, syncer, value, kind, mitre_id, name):
        parsed, _rels = syncer.parse_attribute(_text_attr(value), _EVENT)
        assert parsed is not None
        assert (parsed["type"], parsed["mitre_id"], parsed["name"]) == (kind, mitre_id, name)

    def test_a_text_value_that_is_no_attack_entry_stays_an_indicator(self, syncer):
        for value in ("T800 controller", "some-mutex-name", "S3 bucket listing"):
            parsed, _rels = syncer.parse_attribute(_text_attr(value), _EVENT)
            assert parsed is not None and parsed.get("indicator_type") == "unknown", value


def _dropped(reason: str) -> float:
    from prometheus_client import REGISTRY

    return REGISTRY.get_sample_value("edgeguard_misp_attributes_dropped_total", {"reason": reason}) or 0.0


class TestARewrittenValueIsSkipped:
    @pytest.mark.parametrize("value", sorted(MISP_REWRITTEN.values()))
    def test_the_rewritten_values_create_no_item(self, syncer, caplog, value):
        caplog.set_level(logging.WARNING)
        before = _dropped("attack_id_invalid")
        parsed, rels = syncer.parse_attribute(_text_attr(value), _EVENT)
        assert (parsed, rels) == (None, [])
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("[ATTACK-VALUE]" in m and repr(value) in m for m in warnings), warnings
        assert syncer.stats["attack_values_skipped"] == 1
        assert _dropped("attack_id_invalid") == before + 1

    @pytest.mark.parametrize("value", ["T1059:", "T1059.0031 - Name", "S12345 - Tool", "TA00021 - Tactic", "T1059abc"])
    def test_a_value_with_no_valid_attack_id_creates_no_item(self, syncer, value):
        parsed, rels = syncer.parse_attribute(_text_attr(value), _EVENT)
        assert (parsed, rels) == (None, [])

    def test_the_run_summary_reports_the_count(self):
        source = (SRC / "run_misp_to_neo4j.py").read_text(encoding="utf-8")
        assert 'self.stats.get("attack_values_skipped"' in source
        assert "[ATTACK-VALUE]" in source


class TestTheStixConversionReadsBothForms:
    @pytest.mark.parametrize(
        "value, stix_type, name, external_id",
        [
            ("T1059.003 - Windows Command Shell", "attack-pattern", "Windows Command Shell", "T1059.003"),
            ("T1059.003: Windows Command Shell", "attack-pattern", "Windows Command Shell", "T1059.003"),
            ("S0005 - Windows Credential Editor", "tool", "Windows Credential Editor", "S0005"),
            ("TA0002 - Execution", "x-mitre-tactic", "Execution", "TA0002"),
        ],
    )
    def test_attack_values_convert(self, syncer, value, stix_type, name, external_id):
        obj = syncer._attribute_to_stix21(_text_attr(value), "event-uuid", ["global"])
        assert obj is not None
        assert (obj["type"], obj["name"], obj["external_references"][0]["external_id"]) == (
            stix_type,
            name,
            external_id,
        )

    def test_a_rewritten_value_converts_to_nothing(self, syncer):
        assert syncer._attribute_to_stix21(_text_attr("T1059.00%WINDIR%\\Command Shell"), "e", ["global"]) is None


# --------------------------------------------------------------------------- the helper
class TestParseAttackValue:
    def test_forms(self):
        from attack_values import AttackValue, format_attack_value, looks_like_attack_value, parse_attack_value

        assert format_attack_value("T1059.003", "Windows Command Shell") == "T1059.003 - Windows Command Shell"
        assert parse_attack_value("T1059.003 - Windows Command Shell") == AttackValue(
            "technique", "T1059.003", "Windows Command Shell"
        )
        assert parse_attack_value("T1059.003: Windows Command Shell") == AttackValue(
            "technique", "T1059.003", "Windows Command Shell"
        )
        assert parse_attack_value("TA0104 - Execution") == AttackValue("tactic", "TA0104", "Execution")
        assert parse_attack_value("S0005: Windows Credential Editor") == AttackValue(
            "tool", "S0005", "Windows Credential Editor"
        )
        assert parse_attack_value("T1059") == AttackValue("technique", "T1059", "")
        for rewritten in MISP_REWRITTEN.values():
            assert parse_attack_value(rewritten) is None
            assert looks_like_attack_value(rewritten)
        for other in ("T800 controller", "S3 bucket", "", "Mimikatz", "t1059 - lower case", "G0016 - APT29"):
            assert parse_attack_value(other) is None
            assert not looks_like_attack_value(other)


# --------------------------------------------------------------------------- the acceptance check
class TestAcceptanceCheckNamesTheNineEntries:
    def test_the_check_asks_for_the_nine_entries(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "verify_fresh_baseline_attack_values", SRC.parent / "scripts" / "verify_fresh_baseline.py"
        )
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        technique_ids = {mitre_id for mitre_id, _name, _phase in _WINDOWS_TECHNIQUES}
        assert set(mod._MANGLED_TECHNIQUES) == technique_ids
        assert set(mod._MANGLED_TOOLS) == {"S0005"}
        assert len(technique_ids) + len(mod._MANGLED_TOOLS) == 9
        assert "Import Regexp" in mod._MANGLED_TOOLS_HINT
