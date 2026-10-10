"""Pins for the remaining R6 build: ``(ThreatActor)-[:USES_MALWARE]->(Malware)`` and
``(ThreatActor)-[:USES_TOOL]->(Tool)`` from MITRE's explicit group → software ``uses`` relationships.

Before: the MITRE collector kept ``uses`` rows only when the target was a technique, so the
group → software claims never left the bundle (the legacy CLI path inferred ATTRIBUTED_TO from them,
``mitre_derived``). Now: collector → ``uses_malware`` / ``uses_tools`` on the actor item →
``MITRE_USES_TECHNIQUES.m`` / ``.s`` in MISP → parser → ThreatActor node → build_relationships
Q2b / Q2c with ``mitre_explicit`` 0.95.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from collectors import mitre_collector as mc  # noqa: E402
from collectors.misp_writer import _technique_meta  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

_BUILD_REL = _SRC / "build_relationships.py"
_ACCEPT = _SRC.parent / "scripts" / "verify_fresh_baseline.py"
_EVENT = {"id": 4242, "info": "EdgeGuard-mitre_attck-2026-10-01", "date": "2026-10-01", "Tag": []}


def _bundle_objects():
    ext = lambda eid: [{"source_name": "mitre-attack", "external_id": eid}]  # noqa: E731
    return [
        {
            "type": "intrusion-set",
            "id": "intrusion-set--1",
            "name": "APT28",
            "aliases": ["Fancy Bear"],
            "created": "2020-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "external_references": ext("G0007"),
        },
        {
            "type": "malware",
            "id": "malware--1",
            "name": "X-Agent",
            "x_mitre_aliases": ["CHOPSTICK"],
            "external_references": ext("S0161"),
        },
        {"type": "tool", "id": "tool--1", "name": "Mimikatz", "external_references": ext("S0002")},
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1",
            "name": "Command and Scripting Interpreter",
            "external_references": ext("T1059"),
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        },
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--1",
            "target_ref": "malware--1",
        },
        {
            "type": "relationship",
            "id": "relationship--2",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--1",
            "target_ref": "tool--1",
        },
        {
            "type": "relationship",
            "id": "relationship--3",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--1",
            "target_ref": "attack-pattern--1",
        },
        {
            "type": "relationship",
            "id": "relationship--4",
            "relationship_type": "uses",
            "source_ref": "malware--1",
            "target_ref": "attack-pattern--1",
        },
    ]


def _collector():
    c = mc.MITRECollector.__new__(mc.MITRECollector)
    c.tag = "mitre_attck"
    return c


class TestCollectorKeepsGroupToSoftwareUses:
    def test_actor_item_carries_uses_malware_and_uses_tools(self):
        parsed = _collector()._parse_bundle(_bundle_objects(), domain="enterprise", kill_chain_name="mitre-attack")
        actor = next(a for a in parsed["actors"] if a["name"] == "APT28")
        assert actor["uses_malware"] == ["X-Agent"]
        assert actor["uses_tools"] == ["S0002"], "tools travel as ATT&CK S-ids (Tool nodes are keyed by mitre_id)"
        assert actor["uses_techniques"] == ["T1059"], "technique uses are unchanged"
        malware = next(m for m in parsed["malware"] if m["name"] == "X-Agent")
        assert malware["uses_techniques"] == ["T1059"] and "uses_malware" not in malware

    def test_relationship_rows_keep_the_software_claims(self):
        parsed = _collector()._parse_bundle(_bundle_objects(), domain="enterprise", kill_chain_name="mitre-attack")
        sw = [r for r in parsed["relationships"] if r["type"] == "uses_software"]
        # malware is keyed by name in the collector id_map (no S-id kept); tools carry their S-id
        assert {(r["target_type"], r["target_name"], r["target_mitre_id"]) for r in sw} == {
            ("malware", "X-Agent", ""),
            ("tool", "Mimikatz", "S0002"),
        }
        assert all(r["source_name"] == "APT28" for r in sw)

    def test_domain_merge_unions_the_new_lists(self):
        primary = {
            "actors": [
                {"name": "APT28", "uses_techniques": ["T1059"], "uses_malware": ["X-Agent"], "uses_tools": ["S0002"]}
            ],
            "malware": [],
            "tools": [],
            "techniques": [],
            "tactics": [],
            "relationships": [],
        }
        secondary = {
            "actors": [
                {
                    "name": "APT28",
                    "uses_techniques": ["T0800"],
                    "uses_malware": ["X-Agent", "Zebrocy"],
                    "uses_tools": ["S0002", "S0005"],
                }
            ],
            "malware": [],
            "tools": [],
            "techniques": [],
            "tactics": [],
            "relationships": [],
        }
        merged = (
            mc.MITRECollector._merge_domain_bundles(primary, secondary)
            if hasattr(mc.MITRECollector._merge_domain_bundles, "__func__")
            else _collector()._merge_domain_bundles(primary, secondary)
        )
        actor = merged["actors"][0]
        assert actor["uses_techniques"] == ["T1059", "T0800"]
        assert actor["uses_malware"] == ["X-Agent", "Zebrocy"]
        assert actor["uses_tools"] == ["S0002", "S0005"]


class TestRoundTripThroughMisp:
    def test_technique_meta_carries_m_and_s_only_when_present(self):
        assert _technique_meta(
            {"uses_techniques": ["T1059"], "uses_malware": ["X-Agent"], "uses_tools": ["S0002"]}
        ) == {"t": ["T1059"], "m": ["X-Agent"], "s": ["S0002"]}
        assert _technique_meta({"uses_techniques": ["T1059"], "uses_malware": [], "uses_tools": None}) == {
            "t": ["T1059"]
        }
        assert len(_technique_meta({"uses_malware": [f"m{i}" for i in range(300)]})["m"]) == 200, "capped"

    def test_parser_rehydrates_uses_malware_and_uses_tools_on_actors(self):
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        comment = 'MITRE_USES_TECHNIQUES:{"t":["T1059"],"m":["X-Agent"," Zebrocy "],"s":["S0002",""]}'
        attr = {
            "type": "threat-actor",
            "value": "APT28",
            "uuid": "10000000-0000-0000-0000-00000000abcd",
            "comment": comment,
            "Tag": [],
        }
        item, _ = syncer.parse_attribute(attr, _EVENT)
        assert item["uses_techniques"] == ["T1059"]
        assert item["uses_malware"] == ["X-Agent", "Zebrocy"]
        assert item["uses_tools"] == ["S0002"]

    def test_merge_actor_persists_both_lists_as_accumulating_arrays(self):
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        client._connection_healthy = True
        session = MagicMock()
        session.run.return_value.single.return_value = None
        client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
        client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
        client.merge_actor(
            {
                "name": "APT28",
                "tag": "mitre_attck",
                "zone": ["global"],
                "uses_malware": ["X-Agent"],
                "uses_tools": ["S0002"],
            },
            source_id="mitre_attck",
        )
        cypher, kwargs = session.run.call_args_list[1][0][0], session.run.call_args_list[1][1]
        assert kwargs["uses_malware"] == ["X-Agent"] and kwargs["uses_tools"] == ["S0002"]
        assert "n.uses_malware" in cypher and "n.uses_tools" in cypher
        src = (_SRC / "neo4j_client.py").read_text()
        block = src[src.index("_ARRAY_ACCUMULATE_PROPS = frozenset(") :][:600]
        assert '"uses_malware"' in block and '"uses_tools"' in block, "accumulate across sources like uses_techniques"


def _assigned_string(name: str) -> str:
    tree = ast.parse(_BUILD_REL.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return "".join(
                c.value for c in ast.walk(node.value) if isinstance(c, ast.Constant) and isinstance(c.value, str)
            )
    raise AssertionError(f"{name} not found")


class TestBuildRelationshipsSteps:
    @pytest.mark.parametrize(
        "name, prop, target, edge",
        [
            (
                "_q2b_inner",
                "uses_malware",
                "(m:Malware {name: toLower(trim(mname))})",
                "USES_MALWARE",
            ),
            ("_q2c_inner", "uses_tools", "(t:Tool {mitre_id: tid})", "USES_TOOL"),
        ],
    )
    def test_inner_query_shape(self, name, prop, target, edge):
        body = _assigned_string(name)
        assert f"UNWIND a.{prop} AS" in body and f"MATCH {target}" in body
        assert f"MERGE (a)-[r:{edge}]->" in body
        _, _, rest = body.partition("ON CREATE SET ")
        on_create, _, after = rest.partition(" SET ")
        assert "match_type" not in on_create
        assert (
            'r.match_type = "mitre_explicit"' in after
            and "r.confidence_score = 0.95" in after
            and "r.edgeguard_managed = true" in after
        )
        assert "aliases" not in body, (
            "never match on m.aliases — rehydrated from untrusted MISP tags (PR-N14 forgery vector)"
        )
        assert "'" not in body, (
            "double quotes only — the inner query is wrapped in single quotes for apoc.periodic.iterate"
        )

    def test_steps_run_right_after_q2_with_skip_queries_and_own_stats_keys(self):
        text = _BUILD_REL.read_text()
        pos = [re.search(rf"\[LINK\] {s}/\d+ ", text).start() for s in ("2", "2b", "2c", "3a")]
        assert pos == sorted(pos)
        assert '"uses_malware"' in text and '"uses_tool"' in text
        assert "_q2b_skip" in text and "_q2c_skip" in text

    def test_step_count_is_eighteen(self):
        text = _BUILD_REL.read_text()
        banners = re.findall(r"\[LINK\] (\w+)/(\d+) ", text)
        assert {t for _, t in banners} == {"18"} and len(banners) == 18
        assert "failures=%d/18" in text


class TestAcceptanceScript:
    def test_types_policed_and_checks_present(self):
        script = _ACCEPT.read_text()
        assert '    "USES_MALWARE",\n    "USES_TOOL",\n' in script
        assert 'rep.add("uses_malware_complete"' in script and 'rep.add("uses_tool_complete"' in script
        assert 'None if (r.get("claims") or 0) == 0 else' in script, "informational until the R6 collector has run"
