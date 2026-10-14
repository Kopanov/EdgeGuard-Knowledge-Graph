"""Regular-update linking (2026-10, audit follow-up): the families and adversaries an OTX pulse
names travel on every indicator of the pulse, so IOCs of a LATER pulse that names an
already-known family still get their edges.

Why: the sync pairs an IOC with the malware/actor named in the same pulse only when both are
in the same run. After the baseline a known family is a cross-event duplicate in MISP (PR-F7
dedupe) and is never re-pushed, so a later pulse's IOCs had no family in their event and got no
INDICATES / ATTRIBUTED_TO. Path: collector ``pulse_malware_families`` / ``pulse_malware_actor_pairs`` →
``OTX_META.mf`` / ``.pa`` → parser → ``Indicator.pulse_malware_families`` / ``.pulse_malware_actor_pairs``
→ build_relationships Q9b (INDICATES) and Q2d (ATTRIBUTED_TO), ``otx_pulse`` 0.6, ON CREATE only.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from build_rel_queries import assigned_query  # noqa: E402

from collectors import otx_collector as oc  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

_BUILD_REL = (_SRC / "build_relationships.py").read_text()
_EVENT = {"id": 7, "info": "EdgeGuard-alienvault_otx-2026-10-10", "date": "2026-10-10", "Tag": []}


def _assigned_string(name: str) -> str:
    # 2026-10 (relationship provenance): the queries are assembled from shared fragments, so the
    # helper evaluates the assignment (the text that runs) instead of joining its literals.
    return assigned_query(name)


# --------------------------------------------------------------------------- collector
class TestCollectorStampsPulseFamiliesAndAdversariesOnIndicators:
    def _collector(self):
        c = oc.OTXCollector.__new__(oc.OTXCollector)
        c.api_key = "test-otx-key-64chars" + "a" * 44
        c.tag = "alienvault_otx"
        c.session = MagicMock()
        c.rate_limiter = MagicMock()
        c.rate_limiter.wait_if_needed = MagicMock()
        c._last_http_status = 200
        c.circuit_breaker = MagicMock()
        c.circuit_breaker.can_execute.return_value = True
        c.misp_writer = None
        c.source_name = "otx"
        c.health_check = MagicMock(return_value=True)
        return c

    @staticmethod
    def _pulse(pid, families, adversary, iocs):
        now = datetime.now(timezone.utc).isoformat()
        return {
            "id": pid,
            "name": f"pulse {pid}",
            "created": now,
            "modified": now,
            "adversary": adversary,
            "TLP": "green",
            "attack_ids": ["T1059"],
            "malware_families": families,
            "indicators": [{"type": "IPv4", "indicator": v, "description": "ioc"} for v in iocs],
        }

    def _collect(self, pulses):
        c = self._collector()
        pages = iter([pulses])
        with (
            patch.object(c, "check_service_available", return_value=True),
            patch.object(c, "_fetch_pulses", side_effect=lambda **kw: next(pages, [])),
            patch("collectors.otx_collector.time.sleep", lambda *_a, **_k: None),
            patch("collectors.otx_collector.get_source_incremental", return_value={}),
            patch("collectors.otx_collector.update_source_incremental", lambda *_a, **_k: None),
        ):
            return c.collect(limit=10, push_to_misp=False)

    def test_indicator_carries_the_pulse_families_and_cleaned_adversaries(self):
        items = self._collect(
            [
                self._pulse(
                    "p1",
                    ["Emotet", {"name": " TrickBot "}, "unknown", "emotet"],
                    "apt28, fancy bear (apt28)",
                    ["203.0.113.5"],
                )
            ]
        )
        ioc = next(i for i in items if i.get("value") == "203.0.113.5")
        assert ioc["pulse_malware_families"] == ["Emotet", "TrickBot"], (
            "placeholders and case-duplicates dropped, order kept"
        )
        assert ioc["pulse_malware_actor_pairs"] == [
            "Emotet::apt28",
            "Emotet::fancy bear",
            "TrickBot::apt28",
            "TrickBot::fancy bear",
        ], "same-pulse family × adversary pairs; the adversary goes through actor hygiene"
        malware = next(i for i in items if i.get("type") == "malware" and i["name"] == "Emotet")
        assert "pulse_malware_families" not in malware, "lists live on indicators only"

    def test_same_ioc_in_two_pulses_unions_the_lists(self):
        items = self._collect(
            [
                self._pulse("p1", ["Emotet"], "apt28", ["203.0.113.5"]),
                self._pulse("p2", ["Mirai", "Emotet"], "lazarus group", ["203.0.113.5", "198.51.100.9"]),
            ]
        )
        shared = [i for i in items if i.get("value") == "203.0.113.5"]
        assert len(shared) == 1, "one item per IOC per run"
        assert shared[0]["pulse_malware_families"] == ["Emotet", "Mirai"]
        assert shared[0]["pulse_malware_actor_pairs"] == [
            "Emotet::apt28",
            "Mirai::lazarus group",
            "Emotet::lazarus group",
        ], "pairs stay per pulse: p1 named (Emotet, apt28); p2 named (Mirai, Emotet) with lazarus"
        assert "Mirai::apt28" not in shared[0]["pulse_malware_actor_pairs"], "no cross-pulse pairing (Bugbot on #145)"
        assert shared[0]["report_ids"] == ["p2"]
        other = next(i for i in items if i.get("value") == "198.51.100.9")
        assert other["pulse_malware_families"] == ["Mirai", "Emotet"], (
            "the second pulse's own order, untouched by the fold"
        )

    def test_pair_encoder_is_same_pulse_only_and_capped(self):
        assert oc._pulse_actor_pairs(["Emotet", "Mirai"], ["apt28"]) == ["Emotet::apt28", "Mirai::apt28"]
        assert oc._pulse_actor_pairs(["Emotet"], []) == [] and oc._pulse_actor_pairs([], ["apt28"]) == []
        assert len(oc._pulse_actor_pairs([f"f{i}" for i in range(20)], [f"a{i}" for i in range(5)])) == 50

    def test_helper_caps_and_filters(self):
        assert oc._pulse_family_names([f"fam{i}" for i in range(40)]) == [f"fam{i}" for i in range(20)]
        assert oc._pulse_family_names([None, "", "N/A", {"name": "x"}, {"other": 1}]) == ["x"]


# --------------------------------------------------------------------------- writer → parser round trip
def _writer():
    return MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)


class TestMispRoundTrip:
    def _indicator(self, **extra):
        base = {
            "indicator_type": "ipv4",
            "value": "203.0.113.5",
            "zone": ["global"],
            "tag": "alienvault_otx",
            "source": ["alienvault_otx"],
            "confidence_score": 0.5,
            "pulse_id": "p1",
            "pulse_name": "pulse p1",
        }
        base.update(extra)
        return base

    def test_writer_emits_mf_and_adv_only_when_present(self):
        attr = _writer().create_attribute(
            self._indicator(pulse_malware_families=["Emotet", "TrickBot"], pulse_malware_actor_pairs=["Emotet::apt28"])
        )
        meta = json.loads(attr["comment"][len("OTX_META:") :])
        assert meta["mf"] == ["Emotet", "TrickBot"] and meta["pa"] == ["Emotet::apt28"]
        attr2 = _writer().create_attribute(self._indicator())
        meta2 = json.loads(attr2["comment"][len("OTX_META:") :])
        assert "mf" not in meta2 and "pa" not in meta2, "empty lists are pruned to keep the comment small"
        attr3 = _writer().create_attribute(
            self._indicator(
                pulse_malware_families=[f"f{i}" for i in range(40)],
                pulse_malware_actor_pairs=[f"f{i}::a{i}" for i in range(80)],
            )
        )
        meta3 = json.loads(attr3["comment"][len("OTX_META:") :])
        assert len(meta3["mf"]) == 20 and len(meta3["pa"]) == 50

    def test_otx_meta_is_written_for_every_pulse_indicator_not_only_those_with_attack_ids(self):
        """Pre-existing gap found here: OTX_META was emitted only when the pulse had attack_ids or
        targeted_countries, so IOCs of other pulses lost pulse_id / report_ids and could not be
        grouped by the sync at all."""
        attr = _writer().create_attribute(self._indicator())  # pulse_id only, no attack_ids
        assert attr["comment"].startswith("OTX_META:")
        assert json.loads(attr["comment"][len("OTX_META:") :])["pulse_id"] == "p1"

    def test_parser_rehydrates_the_lists_on_the_indicator(self):
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        comment = (
            'OTX_META:{"pulse_id":"p1","mf":["Emotet"," TrickBot ",""],"pa":["Emotet::apt28","broken-no-separator"]}'
        )
        attr = {
            "type": "ip-src",
            "value": "203.0.113.5",
            "uuid": "20000000-0000-0000-0000-00000000abcd",
            "comment": comment,
            "Tag": [],
        }
        item, _ = syncer.parse_attribute(attr, _EVENT)
        assert item["pulse_malware_families"] == ["Emotet", "TrickBot"]
        assert item["pulse_malware_actor_pairs"] == ["Emotet::apt28"], "entries without the separator are dropped"
        item2, _ = syncer.parse_attribute({**attr, "comment": 'OTX_META:{"pulse_id":"p1"}'}, _EVENT)
        assert "pulse_malware_families" not in item2 and "pulse_malware_actor_pairs" not in item2


# --------------------------------------------------------------------------- node write
class TestIndicatorBatchAccumulatesTheLists:
    def _client(self):
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        client._connection_healthy = True
        session = MagicMock()
        session.run.return_value.single.return_value = None
        client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
        client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
        return client, session

    def test_batch_rows_carry_the_lists_and_cypher_accumulates_them(self):
        client, session = self._client()
        client.merge_indicators_batch(
            [
                {
                    "indicator_type": "ipv4",
                    "value": "203.0.113.5",
                    "tag": "alienvault_otx",
                    "zone": ["global"],
                    "pulse_malware_families": ["Emotet"],
                    "pulse_malware_actor_pairs": ["Emotet::apt28"],
                }
            ],
            source_id="misp",
        )
        batch_rows = None
        cyphers = []
        for call in session.run.call_args_list:
            cyphers.append(call.args[0] if call.args else "")
            for v in list(call.kwargs.values()) + list(call.args[1:]):
                if isinstance(v, list) and v and isinstance(v[0], dict) and "pulse_malware_families" in v[0]:
                    batch_rows = v
        assert batch_rows is not None, [list(c.kwargs) for c in session.run.call_args_list]
        assert batch_rows[0]["pulse_malware_families"] == ["Emotet"] and batch_rows[0]["pulse_malware_actor_pairs"] == [
            "Emotet::apt28"
        ]
        merged = "\n".join(cyphers)
        assert "n.pulse_malware_families = " in merged and "coalesce(item.pulse_malware_families, [])" in merged
        assert "n.pulse_malware_actor_pairs = " in merged and "coalesce(item.pulse_malware_actor_pairs, [])" in merged
        assert "coalesce(n.pulse_malware_families, [])" in merged, "accumulates across pulses, never overwrites"


# --------------------------------------------------------------------------- build_relationships steps
class TestPulseScopedSteps:
    def test_q9b_links_indicator_to_malware_by_canonical_name_only(self):
        body = _assigned_string("_q9b_inner")
        assert "UNWIND i.pulse_malware_families AS fam" in body and "MATCH (m:Malware {name: fname})" in body
        assert "MERGE (i)-[r:INDICATES]->(m)" in body
        assert 'ON CREATE SET r.confidence_score = 0.6, r.match_type = "otx_pulse"' in body
        unconditional = body.split(" SET r.updated_at", 1)[1]
        assert "confidence_score" not in unconditional and "match_type" not in unconditional, (
            "ON CREATE only: never downgrade an IOC-level malware_family (0.8)"
        )
        assert "aliases" not in body, "aliases are untrusted (PR-N14) — canonical name only"
        assert "'" not in body, "double quotes only — wrapped in single quotes for apoc.periodic.iterate"
        assert "r.edgeguard_managed = true" in body and "r.misp_event_ids" in body
        skip = _assigned_string("_q9b_skip")
        assert "NOT EXISTS { MATCH (m:Malware {name: fname}) }" in skip

    def test_q2d_pairs_malware_and_actor_from_the_indicator_lists(self):
        outer = _assigned_string("_q2d_outer")
        assert "UNWIND i.pulse_malware_actor_pairs AS pair RETURN DISTINCT pair" in outer, "one same-pulse pair per row"
        body = _assigned_string("_q2d_inner")
        assert body.startswith('WITH $pair AS pair WITH split(pair, "::") AS parts WHERE size(parts) = 2')
        assert "UNWIND fams" not in body and "UNWIND advs" not in body, (
            "no family × adversary cross product (Bugbot on #145)"
        )
        assert "MATCH (m:Malware {name: fname}) MATCH (a:ThreatActor {name: aname})" in body
        assert "MERGE (m)-[r:ATTRIBUTED_TO]->(a)" in body
        assert 'ON CREATE SET r.confidence_score = 0.6, r.match_type = "otx_pulse"' in body
        assert "'" not in body and "aliases" not in body

    def test_banners_and_order(self):
        banners = re.findall(r"\[LINK\] (\w+)/20 ", _BUILD_REL)
        assert banners.index("2c") + 1 == banners.index("2d") and banners.index("9") + 1 == banners.index("9b")
        assert len(banners) == 20

    def test_acceptance_check_present(self):
        script = (_SRC.parent / "scripts" / "verify_fresh_baseline.py").read_text()
        assert 'rep.add("pulse_indicates_complete"' in script and "i.pulse_malware_families" in script
