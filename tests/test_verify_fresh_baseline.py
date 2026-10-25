"""Unit tests for ``scripts/verify_fresh_baseline.py`` — the read-only acceptance gate that
declares a fresh baseline good (2026-10 fresh-baseline PR).

The script talks to Neo4j over HTTP; here ``_post`` is replaced by a dispatcher keyed on
Cypher fragments, so each check's pass/fail/informational logic is exercised on canned rows.
The point of these tests is the false-positive surface the owner asked about: a check must
not fail when nothing is wrong (short smoke baselines, non-EdgeGuard relationship types,
marker-stamped ResilMesh-model nodes that never carry ``tlp``) and must still fail when the
invariant is really broken.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, FrozenSet, List, Optional
from unittest.mock import MagicMock

import pytest

_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "scripts", "verify_fresh_baseline.py")
_SRC = Path(__file__).resolve().parent.parent / "src"

# What the writers of the baseline DAG put on each relationship type, read from the code (2026-10
# relationship provenance; ``TestContractIsWhatTheWritersWrite`` derives the same table from their
# Cypher). The scan rows of a correct graph follow it.
_LISTS: FrozenSet[str] = frozenset({"sources", "source_refs", "misp_event_ids"})
_WRITTEN_BY_TYPE: Dict[str, FrozenSet[str]] = {
    **{
        t: _LISTS | {"match_type"}
        for t in (
            "EMPLOYS_TECHNIQUE",
            "IMPLEMENTS_TECHNIQUE",
            "USES_TECHNIQUE",
            "ATTRIBUTED_TO",
            "INDICATES",
            "EXPLOITS",
            "TARGETS",
            "AFFECTS",
            "IN_TACTIC",
            "SUBTECHNIQUE_OF",
            "USES_MALWARE",
            "USES_TOOL",
        )
    },
    # 2026-10-15: the campaign links state their evidence (campaign_grouping); 2026-10-16: and name
    # the relationship types they rest on.
    **{t: _LISTS | {"match_type", "evidence_types"} for t in ("RUNS", "PART_OF_CAMPAIGN")},
    **{t: _LISTS for t in ("REFERS_TO",)},
    **{
        t: frozenset({"sources", "misp_event_ids"})
        for t in ("HAS_CVSS_v2", "HAS_CVSS_v30", "HAS_CVSS_v31", "HAS_CVSS_v40")
    },
    "SOURCED_FROM": frozenset({"source", "source_refs", "misp_event_ids"}),
}
_SCAN_PROPS = ("sources", "source_refs", "misp_event_ids", "match_type", "source", "evidence_types")


def _scan_row(rel_type, edges=10, managed=None, written=None, empty_events=0, legacy=0):
    """One row of the per-type relationship scan (checks 12b / 12c)."""
    managed = edges if managed is None else managed
    written = _WRITTEN_BY_TYPE.get(rel_type, frozenset()) if written is None else written
    row = {"type": rel_type, "edges": edges, "managed": managed, "empty_misp_event_ids": empty_events}
    row.update({f"with_{p}": managed if p in written else 0 for p in _SCAN_PROPS})
    row["legacy_keys"] = legacy
    return row


def _healthy_scan() -> List[Dict[str, Any]]:
    rows = [_scan_row(t) for t in sorted(_WRITTEN_BY_TYPE)]
    # A campaign link whose ATTRIBUTED_TO links name no MISP event has an empty list: legitimate.
    rows = [dict(r, empty_misp_event_ids=2) if r["type"] == "RUNS" else r for r in rows]
    # ResilMesh's own edges carry no EdgeGuard provenance and are not judged.
    rows.append(_scan_row("ON", edges=3, managed=0))
    return rows


# ``SOURCED_FROM`` count per ``Source`` node on a correct default baseline: the keyed sources whose
# key the deployment holds delivered, VirusTotal (no key) and the two flag-guarded sources did not,
# and the alias nodes (``otx``, ``cisa``) never receive edges.
_SOURCE_ROWS = [
    {"source_id": "abuseipdb", "sourced_from": 10000},
    {"source_id": "alienvault_otx", "sourced_from": 149000},
    {"source_id": "cisa", "sourced_from": 0},
    {"source_id": "cisa_ics", "sourced_from": 0},
    {"source_id": "cisa_kev", "sourced_from": 1500},
    {"source_id": "feodo_tracker", "sourced_from": 7600},
    {"source_id": "malwarebazaar", "sourced_from": 0},
    {"source_id": "misp", "sourced_from": 0},
    {"source_id": "mitre_attck", "sourced_from": 1900},
    {"source_id": "nvd", "sourced_from": 140000},
    {"source_id": "otx", "sourced_from": 0},
    {"source_id": "ssl_blacklist", "sourced_from": 11000},
    {"source_id": "threatfox", "sourced_from": 7400},
    {"source_id": "urlhaus", "sourced_from": 34000},
    {"source_id": "virustotal", "sourced_from": 0},
]


@pytest.fixture(scope="module")
def vfb():
    spec = importlib.util.spec_from_file_location("verify_fresh_baseline", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules.setdefault("verify_fresh_baseline", mod)
    spec.loader.exec_module(mod)
    return mod


# Check 9b (2026-10, revoked ATT&CK objects): the Technique ids, the ThreatActor nodes and the
# Malware / Tool nodes (canonical name, sources) of a correct graph. The dispatcher answers the three
# queries from these with the ids / names the check passes, as Neo4j would.
_GRAPH_TECHNIQUES = ("T1059", "T1059.001", "T1566.001", "T1574.001", "T1685", "T0800")
_GRAPH_ACTORS = (
    ("apt29", ("mitre_attck", "alienvault_otx")),
    ("oilrig", ("mitre_attck",)),
    ("magic hound", ("mitre_attck",)),
    ("conti team", ("alienvault_otx",)),
)
_GRAPH_SOFTWARE = (
    ("poisonivy", ("mitre_attck",)),
    ("ngrok", ("mitre_attck",)),  # a revoked software's name that its successor also bears
    ("mimikatz", ("mitre_attck", "alienvault_otx")),
    ("darkmoon", ("alienvault_otx",)),  # another source's name: not judged
)


def _revoked_technique_rows(params: Dict[str, Any], techniques=_GRAPH_TECHNIQUES) -> List[Dict[str, Any]]:
    hits = [t for t in techniques if t in set(params["ids"])]
    return [{"techniques": len(techniques), "revoked_ids": len(hits), "examples": hits[:10]}]


def _revoked_group_rows(params: Dict[str, Any], actors=_GRAPH_ACTORS) -> List[Dict[str, Any]]:
    names = set(params["names"])
    revoked = [(n, src) for n, src in actors if n.strip().lower() in names]
    return [
        {
            "mitre_actors": sum(1 for _n, src in actors if "mitre_attck" in src),
            "revoked_groups_from_mitre": sum(1 for _n, src in revoked if "mitre_attck" in src),
            "revoked_names_other_sources": sum(1 for _n, src in revoked if "mitre_attck" not in src),
            "examples_from_mitre": [n for n, src in revoked if "mitre_attck" in src][:10],
            "examples_other_sources": [n for n, src in revoked if "mitre_attck" not in src][:10],
        }
    ]


def _revoked_software_rows(params: Dict[str, Any], software=_GRAPH_SOFTWARE) -> List[Dict[str, Any]]:
    names = set(params["names"])
    mitre = [n for n, src in software if "mitre_attck" in src]  # the query keeps MITRE nodes only
    revoked = [n for n in mitre if n.strip().lower() in names]
    return [{"mitre_software": len(mitre), "revoked_software": len(revoked), "examples": revoked[:10]}]


# Explainability (2026-10): (indicator's cited revoked ids, links to their successors, links that name
# the cited id) — a correct graph records every one.
_GRAPH_CITED = (25135, 24440, 24440)


def _cited_rows(cited=_GRAPH_CITED) -> List[Dict[str, Any]]:
    return [{"cited_revoked_ids": cited[0], "linked": cited[1], "recorded": cited[2]}]


_EPSS_SSVC_ROW = {
    "cves": 141000,
    "with_epss": 139500,
    "epss_score_dates": 1,
    "latest_epss_score_date": "2026-10-11T12:00:25Z",
    "with_ssvc": 61000,
    "ssvc_exploitation_active": 1500,
}


# 2026-10: pulses naming two or more actor nodes. The first are two groups, the second two names of
# one actor (aliases in the canonical reference), so only the first names several actors.
_REPORT_ACTOR_ROWS = [
    {"pid": "68cd617b3eb5b1212d11643d", "names": ["gamaredon", "turla"]},
    {"pid": "6a189defc88ad66cd0a9d87d", "names": ["the gentlemen", "storm-2697"]},
]
# 2026-10: the pulses the OTX collector marked on indicators as naming several actors. The first is
# also on two actor nodes; the second ("Indonesian Banking Sector Threat Landscape", 8 actors) is on no
# actor node as a pulse of several: MISP held its actors already and did not push them again.
_MARKED_PULSES = ["68cd617b3eb5b1212d11643d", "6a4fdf500b5e6dffde939998"]
# 2026-10-16: check 13d on a correct graph: every campaign EdgeGuard built rests on its actor's
# ATTRIBUTED_TO or USES_MALWARE links and has the actor's RUNS.
_CAMPAIGN_EVIDENCE_ROW = {"campaigns": 210, "without_evidence": 0, "without_runs": 0, "runs_without_evidence": 0}
_ATTRIBUTION_ROW = {
    "links": 3212,
    "resting_on_several_actor_reports": 0,
    "naming_several_actor_reports": 0,
    "without_reports": 129,
}


# Check 10a5 (2026-10, Malware twins): the non-MITRE Malware nodes named with an ATT&CK software id
# and the MITRE Malware nodes with the record MITRE delivered (the ``raw_data`` of their SOURCED_FROM
# edge: the sync item without its key property). On a correct graph the only twin left is one whose
# id no MITRE Malware node has and whose base name no other node carries: Mimikatz S0002 is an ATT&CK
# tool. The MITRE nodes hold the names the twin merge folded (``merged_from``, read for check 10a4).
def _mitre_malware_raw(name: str, attack_id: str) -> str:
    return json.dumps(
        {
            "type": "malware",
            "aliases": [name],
            "malware_types": ["malware"],
            "family": name,
            "description": f"[{name}](https://attack.mitre.org/software/{attack_id}) is malware.",
            "tag": "mitre_attck",
            "source": ["mitre_attck"],
        }
    )


_GRAPH_MALWARE_TWINS = ({"name": "mimikatz - s0002", "aliases": []},)
_GRAPH_MITRE_MALWARE = (
    {"name": "cobalt strike", "attack_raw": _mitre_malware_raw("Cobalt Strike", "S0154")},
    {"name": "poisonivy", "attack_raw": _mitre_malware_raw("PoisonIvy", "S0012")},
    {"name": "agent tesla", "attack_raw": None},
)
_GRAPH_FOLDED_MALWARE = (
    {"name": "cobalt strike", "merged_from": ["cobalt strike - s0154"], "mitre": True},
    {"name": "agent tesla", "merged_from": ["agenttesla"], "mitre": True},
    {"name": "poisonivy", "merged_from": None, "mitre": True},
)


# 2026-10-16 (sector evidence, checks 10d-10j; ranked descriptions and indicator aging, check 16): what a
# correct default baseline answers. CISA ICS is off by default (``_SOURCE_ROWS``), so no link carries
# ``advisory_sector`` and no sector is stated; every SOURCED_FROM edge has ``zones``.
_SOURCED_FROM_ZONES_ROW = {"edges": 380000, "with_zones": 380000, "with_stated_zones": 0, "with_stated_refs": 0}
_SECTOR_LABEL_ROWS = [{"label": "zone_classification", "links": 72500, "other_confidence": 0}]
_SECTOR_BREAKDOWN_ROWS = [
    {"type": "AFFECTS", "label": "CVE", "sector": "energy", "match_type": "zone_classification", "c": 1400},
    {"type": "TARGETS", "label": "Indicator", "sector": "finance", "match_type": "zone_classification", "c": 64000},
]
_OTX_LINKS_ROW = {
    "otx_links": 0,
    "on_affects": 0,
    "misplaced": 0,
    "citing_no_stating_report": 0,
    "examples": [],
    "citing_examples": [],
}
# The OTX records of Indicator / ThreatActor / Malware nodes: many give a sector, none states one (the
# default fixture's graph predates the statement; ``--require-otx-industries`` fails on it).
_OTX_RECORDS_ROW = {"otx_records": 148000, "otx_records_with_a_sector": 54250, "otx_records_stating": 0}
_SECTOR_LABEL_COUNT_ROWS = [
    {"type": "AFFECTS", "match_type": "zone_classification", "links": 8500},
    {"type": "TARGETS", "match_type": "zone_classification", "links": 64000},
]
_DESCRIPTION_ROW = {"described": 150000, "without_source": 0, "example_labels": []}
_AGING_ROW = {"indicators": 217000, "without_aging_basis": 0, "without_source_confidence": 0}


def _sector_evidence_rows(s: str) -> Optional[List[Dict[str, Any]]]:
    """The healthy answer to a statement of checks 10d-10j and 16, or None for any other statement. Asked
    first: these statements carry fragments (``source_id: 'cisa_ics'``, ``apoc.meta.cypher.type(r.sources)``)
    that older matchers below key on."""
    if "AS with_stated_zones" in s:
        return [dict(_SOURCED_FROM_ZONES_ROW)]
    if "NOT s.name IN" in s and "AS source, count(*) AS c" in s:
        return []
    if "AS advisory_links" in s:
        return [{"advisory_links": 0, "misplaced": 0, "examples": []}]
    # 2026-10-18 (checks 10l / 10m): no OTX report stated a sector on the default graph's fixture
    if "AS otx_links" in s:
        return [dict(_OTX_LINKS_ROW)]
    if "AS otx_not_labelled" in s:
        return [{"stated": 0, "otx_not_labelled": 0, "examples": []}]
    if "AS otx_records_with_a_sector" in s:
        return [dict(_OTX_RECORDS_ROW)]
    if "count(*) AS links ORDER BY type, match_type" in s:
        return [dict(x) for x in _SECTOR_LABEL_COUNT_ROWS]
    if "] AS other RETURN" in s:
        return []
    if "AS not_labelled" in s:
        return [{"stated": 0, "not_labelled": 0, "examples": []}]
    if "AS other_confidence" in s:
        return [dict(x) for x in _SECTOR_LABEL_ROWS]
    if "r.match_type AS match_type, count(*) AS c ORDER BY type, label, sector, match_type" in s:
        return [dict(x) for x in _SECTOR_BREAKDOWN_ROWS]
    if "AS cisa_and_inferred" in s:
        return []
    if "AS cisa_global" in s:
        return [{"cisa_records": 0, "cisa_global": 0, "without_zones": 0}]
    if "zone_name AS sector, count(*) AS c" in s:
        return []
    if "WHERE 'global' IN z" in s:
        return []
    if "AS without_source," in s:
        return [dict(_DESCRIPTION_ROW)]
    if "AS without_aging_basis" in s:
        return [dict(_AGING_ROW)]
    return None


# Check 10a6 (2026-10-18) on a correct graph: the same-report links of the OTX reports that list CVEs.
_INDICATOR_CVE_ROW = {
    "indicator_cve_links": 8859,
    "cves": 812,
    "indicators": 4310,
    "not_otx_pulse": 0,
    "without_otx_report": 0,
}


def _healthy_rows(statement: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Rows a correct fresh baseline would return, keyed on fragments of each check's Cypher."""
    s = statement
    sector_rows = _sector_evidence_rows(s)
    if sector_rows is not None:
        return sector_rows
    # 2026-10-18: check 10a6, indicators and CVEs named in the same OTX report.
    if "AS indicator_cve_links" in s:
        return [dict(_INDICATOR_CVE_ROW)]
    if "AS indicates_other_targets" in s:
        return [{"indicates_other_targets": 0}]
    if "AS pid WITH pid, collect(DISTINCT a.name) AS names" in s:
        return [{"reports": [dict(x) for x in _REPORT_ACTOR_ROWS], "pulses": 1530}]
    if "UNWIND i.several_actor_pulses AS pid" in s:
        return [{"pulses": list(_MARKED_PULSES), "indicators": 412}]
    if "AS resting_on_several_actor_reports" in s:
        return [dict(_ATTRIBUTION_ROW)]
    # 2026-10-16: checks 13c / 13d (campaign evidence). Before the USES_MALWARE branch below: both
    # statements name that relationship.
    if "AS malware_links" in s:
        return [{"malware_links": 1600, "without_evidence": 0}]
    if "AS runs_without_evidence" in s:
        return [dict(_CAMPAIGN_EVIDENCE_ROW)]
    if "d.name =~ $suffixed" in s:
        return [dict(r) for r in _GRAPH_MALWARE_TWINS]
    if "AS attack_raw" in s:
        return [dict(r) for r in _GRAPH_MITRE_MALWARE]
    if "m.merged_from AS merged_from" in s:
        return [dict(r) for r in _GRAPH_FOLDED_MALWARE]
    if "b.name IN $bases" in s:
        return []
    if "AS ssvc_exploitation_active" in s:
        return [dict(_EPSS_SSVC_ROW)]
    if "AS recorded" in s:
        return _cited_rows()
    if "AS names_folded" in s:
        return [{"actors": 30, "names_folded": 33}]
    if "AS revoked_ids" in s:
        return _revoked_technique_rows(params)
    if "AS revoked_groups_from_mitre" in s:
        return _revoked_group_rows(params)
    if "AS revoked_software" in s:
        return _revoked_software_rows(params)
    if "apoc.meta.stats" in s:
        return [{"nodeCount": 10, "relCount": 10, "labels": {}, "relTypesCount": {}}]
    if "misp_cooccurrence" in s:
        return [{"c": 0}]
    if "match_type: 'mitre_explicit'" in s:
        return [{"c": 0}]
    if "r.match_type IS NULL" in s:
        return [{"c": 0}]
    if "percentileCont" in s:
        return [{"malware_with_attribution": 50, "median_actors": 1.0, "max_actors": 4}]
    if "RETURN type(r) AS rel, r.match_type AS match_type" in s:
        return [{"rel": "INDICATES", "match_type": "otx_pulse", "c": 5}]
    if "AS result_impacts" in s:
        return [{"n": 1000, "cwe": 930, "ref_tags": 570, "cpe_type": 580, "result_impacts": 910}]
    if "OPTIONAL MATCH (t:Technique {mitre_id: id})" in s:
        return [{"id": i, "present": True} for i in params["ids"]]
    if "OPTIONAL MATCH (t:Tool {mitre_id: id})" in s:
        return [{"id": i, "present": True} for i in params["ids"]]
    if "a.name CONTAINS ','" in s:
        return [{"c": 0, "examples": []}]
    if "n.tlp IS NULL" in s:
        return [{"total": 500, "missing": 0}]
    if "n.edgeguard_managed IS NULL AND n.edgeguard_enriched IS NULL" in s:
        return [{"label": "Host", "c": 2}, {"label": "Device", "c": 1}]
    if "r.edgeguard_managed IS NULL RETURN type(r)" in s:
        return [{"type": "ON", "c": 3}]
    if "coalesce(t.attack_domain, 'enterprise') <> coalesce(tc.attack_domain, 'enterprise')" in s:
        return [{"c": 0}]
    if "Technique {attack_domain: 'ics'}" in s:
        return [{"c": 0}]
    if "source_id: 'cisa_ics'" in s:
        return [{"present": False, "edges": 0}]
    if "source_id: 'malwarebazaar'" in s:
        return [{"present": False, "indicators": 0, "sha256_indicators": 0}]
    if "db.relationshipTypes" in s:
        return [{"t": t} for t in ("SOURCED_FROM", "INDICATES", "INVOLVES", "ON")]
    if "'mitre_attck' IN coalesce(a.source, [])" in s:
        return [{"c": 150}]
    if "(g:Sector {name: 'global'})" in s:
        return [{"c": 0}]
    if "pulse_malware_families" in s:
        return [{"claims": 300, "target_missing": 20, "edge_missing": 0}]
    if "USES_MALWARE" in s or "USES_TOOL" in s:
        return [{"claims": 120, "target_missing": 3, "edge_missing": 0}]
    if "SUBTECHNIQUE_OF" in s:
        return [{"subs": 493, "parent_missing": 0, "edge_missing": 0}]
    if "[r:TARGETS|AFFECTS]->(s:Sector)" in s:
        return [
            {"sector": "energy", "label": "CVE", "nodes": 5},
            {"sector": "energy", "label": "ThreatActor", "nodes": 2},
        ]
    if "bidirectional" in s:
        return [{"label": lbl, "total": 7, "bidirectional": 7} for lbl in ("CVSSv30", "CVSSv31", "CVSSv40")]
    if "size(coalesce(r.sources, [])) = 0" in s:
        return []
    if "apoc.meta.cypher.type(r.sources)" in s:
        return [{"edges": 0}]
    if "apoc.meta.cypher.type(n.zone)" in s:
        return [{"nodes": 0}]
    if "UNWIND r.sources AS s" in s:
        return [{"type": "INDICATES", "source": "threatfox", "c": 5}]
    if "AS legacy_keys" in s:
        return _healthy_scan()
    if "AS sourced_from" in s:
        return [dict(x) for x in _SOURCE_ROWS]
    if "AS part_of_to_campaign" in s:
        return [{"part_of_to_campaign": 0, "part_of_campaign_misplaced": 0, "part_of_campaign": 1600, "part_of": 0}]
    if "AS unscored_with_score" in s:
        return [
            {
                "cves": 141000,
                "with_cvss": 126500,
                "scored_without_score": 0,
                "score_not_from_cvss": 0,
                "unscored_with_score": 0,
            }
        ]
    raise AssertionError(f"unexpected statement in test dispatcher: {statement[:120]}")


def _run(vfb, monkeypatch, override=None, **kw):
    def fake_post(statement, params=None, timeout=180):
        rows = _healthy_rows(statement, params or {})
        return override(statement, rows) if override else rows

    monkeypatch.setattr(vfb, "_post", fake_post)
    return vfb.run_checks(
        kw.get("require_ics", False),
        kw.get("require_cisa_ics", False),
        kw.get("require_malwarebazaar", False),
        kw.get("require_otx_industries", False),
    )


def _check(rep, name):
    return next(c for c in rep.checks if c["check"] == name)


class TestHealthyBaselinePasses:
    def test_all_mandatory_checks_pass_on_a_correct_graph(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch)
        assert rep.failed == [], [c["check"] for c in rep.failed]

    def test_optional_ics_checks_are_informational_unless_required(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch)
        assert _check(rep, "ics_techniques_present")["ok"] is None
        assert _check(rep, "cisa_ics_source_present")["ok"] is None
        assert _check(rep, "cisa_stated_sectors_linked_as_advisory_sector")["ok"] is None
        rep = _run(vfb, monkeypatch, require_ics=True, require_cisa_ics=True)
        # no CISA ICS record at all: the presence check fails; the stated-sector check (2026-10-16) has
        # no record that could state a sector and does not judge
        assert {c["check"] for c in rep.failed} == {"ics_techniques_present", "cisa_ics_source_present"}
        assert _check(rep, "cisa_stated_sectors_linked_as_advisory_sector")["ok"] is None

    def test_malwarebazaar_check_is_informational_unless_required(self, vfb, monkeypatch):
        """``--require-malwarebazaar`` (2026-10): off → INFO even with no Source node; on → the Source
        node must exist with at least one sha256 hash indicator sourced from it."""
        rep = _run(vfb, monkeypatch)
        assert _check(rep, "malwarebazaar_source_present")["ok"] is None and rep.failed == []
        rep = _run(vfb, monkeypatch, require_malwarebazaar=True)
        assert [c["check"] for c in rep.failed] == ["malwarebazaar_source_present"]

        def present(statement, rows):
            if "source_id: 'malwarebazaar'" in statement:
                return [{"present": True, "indicators": 812, "sha256_indicators": 812}]
            return rows

        rep = _run(vfb, monkeypatch, override=present, require_malwarebazaar=True)
        assert _check(rep, "malwarebazaar_source_present")["ok"] is True and rep.failed == []

        def source_without_hashes(statement, rows):
            if "source_id: 'malwarebazaar'" in statement:
                return [{"present": True, "indicators": 3, "sha256_indicators": 0}]
            return rows

        rep = _run(vfb, monkeypatch, override=source_without_hashes, require_malwarebazaar=True)
        assert [c["check"] for c in rep.failed] == ["malwarebazaar_source_present"]

    def test_malwarebazaar_check_counts_sha256_hashes_only(self, vfb, monkeypatch):
        seen = {}

        def capture(statement, rows):
            if "source_id: 'malwarebazaar'" in statement:
                seen["stmt"] = statement
            return rows

        _run(vfb, monkeypatch, override=capture)
        assert "i.indicator_type = 'hash'" in seen["stmt"] and "[0-9a-f]{64}" in seen["stmt"]


class TestNoFalsePositives:
    def test_partner_nodes_and_foreign_edges_without_marker_do_not_fail_ownership_checks(self, vfb, monkeypatch):
        """Host / Device nodes and ResilMesh edge types are not EdgeGuard's; unmarked ones are only
        reported. Alert nodes and INVOLVES edges ARE EdgeGuard's since 2026-10 and are policed."""
        rep = _run(vfb, monkeypatch)
        assert _check(rep, "ownership_marker_on_nodes")["ok"] is True
        assert _check(rep, "ownership_marker_on_edges")["ok"] is True
        assert "Alert" in vfb.EDGEGUARD_LABELS and "INVOLVES" in vfb.EDGEGUARD_REL_TYPES
        assert "Host" not in vfb.EDGEGUARD_LABELS

    def test_unmarked_alert_or_involves_fails_ownership_checks(self, vfb, monkeypatch):
        """A node under an EdgeGuard label with neither marker means a writer omitted it (or a
        partner wrote under EdgeGuard's label) — the check must fail, not stay silent."""

        def broken(statement, rows):
            if "n.edgeguard_managed IS NULL AND n.edgeguard_enriched IS NULL" in statement:
                return [{"label": "Alert", "c": 3}]
            if "r.edgeguard_managed IS NULL RETURN type(r)" in statement:
                return [{"type": "INVOLVES", "c": 3}]
            return rows

        rep = _run(vfb, monkeypatch, override=broken)
        assert _check(rep, "ownership_marker_on_nodes")["ok"] is False
        assert _check(rep, "ownership_marker_on_edges")["ok"] is False

    def test_cve_properties_check_is_informational_on_a_short_smoke_baseline(self, vfb, monkeypatch):
        """7-day window: every NVD CVE is younger than the analysis lag → n below the floor →
        informational, never FAIL (day-old CVEs legitimately have no ref_tags / cpe_type)."""

        def few(statement, rows):
            if "AS result_impacts" in statement:
                return [{"n": 12, "cwe": 2, "ref_tags": 0, "cpe_type": 0, "result_impacts": 3}]
            return rows

        rep = _run(vfb, monkeypatch, override=few)
        c = _check(rep, "cve_resilmesh_properties_present")
        assert c["ok"] is None and "informational" in c["detail"]["note"]
        assert rep.failed == []

    def test_cve_properties_check_scopes_to_analysed_cves(self, vfb, monkeypatch):
        seen = {}

        def capture(statement, rows):
            if "AS result_impacts" in statement:
                seen["stmt"] = statement
            return rows

        _run(vfb, monkeypatch, override=capture)
        assert "duration({days: $lag})" in seen["stmt"] and "c.published IS NOT NULL" in seen["stmt"]
        assert vfb._NVD_ANALYSIS_LAG_DAYS >= 30

    def test_tlp_check_uses_an_allowlist_of_misp_parsed_labels(self, vfb, monkeypatch):
        seen = {}

        def capture(statement, rows):
            if "n.tlp IS NULL" in statement:
                seen["stmt"] = statement
            return rows

        monkeypatch.setattr(
            vfb, "_post", lambda st, params=None, timeout=180: capture(st, _healthy_rows(st, params or {}))
        )
        # the label list travels as a parameter — assert via the module constant + the query shape
        vfb.run_checks(False, False)
        assert "any(l IN labels(n) WHERE l IN $labels)" in seen["stmt"]
        assert set(vfb._TLP_LABELS) == {
            "Indicator",
            "CVE",
            "Vulnerability",
            "Malware",
            "ThreatActor",
            "Technique",
            "Tactic",
            "Tool",
        }
        for not_required in ("Source", "Sector", "Campaign", "CVSSv31", "Host", "Alert", "IP"):
            assert not_required not in vfb._TLP_LABELS


class TestUsesClaimsAreMandatoryOnceMitreActorsExist:
    """2026-10 audit: `claims == 0` used to be informational, but after the re-feed the MITRE collector
    always runs, so zero claims means the `m` / `s` lists were lost in transit — the exact defect
    the check exists for. The gate must fail, not print INFO."""

    def test_zero_claims_fail_when_mitre_actors_exist(self, vfb, monkeypatch):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [{"claims": 0, "target_missing": 0, "edge_missing": 0}]
                if ("USES_MALWARE" in st or "USES_TOOL" in st)
                else rows
            ),
        )
        assert {c["check"] for c in rep.failed} == {"uses_malware_complete", "uses_tool_complete"}
        assert _check(rep, "uses_malware_complete")["detail"]["mitre_actors"] == 150

    def test_informational_only_while_no_mitre_actor_exists(self, vfb, monkeypatch):
        def override(st, rows):
            if "'mitre_attck' IN coalesce(a.source, [])" in st:
                return [{"c": 0}]
            if "USES_MALWARE" in st or "USES_TOOL" in st:
                return [{"claims": 0, "target_missing": 0, "edge_missing": 0}]
            return rows

        rep = _run(vfb, monkeypatch, override=override)
        assert _check(rep, "uses_malware_complete")["ok"] is None and _check(rep, "uses_tool_complete")["ok"] is None
        assert rep.failed == []


class TestRealBreakageStillFails:
    @pytest.mark.parametrize(
        "fragment, bad_rows, check",
        [
            ("misp_cooccurrence", [{"c": 29901}], "no_cooccurrence_edges"),
            ("match_type: 'mitre_explicit'", [{"c": 7}], "mitre_explicit_only_from_mitre_nodes"),
            ("r.match_type IS NULL", [{"c": 1}], "attributed_to_has_match_type"),
            ("a.name CONTAINS ','", [{"c": 2, "examples": ["APT28, Fancy Bear"]}], "no_composite_actor_names"),
            ("n.tlp IS NULL", [{"total": 500, "missing": 9}], "tlp_on_every_node"),
            ("coalesce(t.attack_domain, 'enterprise') <>", [{"c": 3}], "in_tactic_same_domain"),
            # 2026-10 audit: negative rows for the R6 / sector checks (they only had happy-path coverage)
            ("SUBTECHNIQUE_OF", [{"subs": 493, "parent_missing": 0, "edge_missing": 7}], "subtechnique_of_complete"),
            ("USES_MALWARE", [{"claims": 120, "target_missing": 3, "edge_missing": 2}], "uses_malware_complete"),
            ("USES_TOOL", [{"claims": 40, "target_missing": 0, "edge_missing": 1}], "uses_tool_complete"),
            ("(g:Sector {name: 'global'})", [{"c": 137948}], "no_global_sector_edges"),
            (
                "pulse_malware_families",
                [{"claims": 300, "target_missing": 20, "edge_missing": 4}],
                "pulse_indicates_complete",
            ),
            ("bidirectional", [{"label": "CVSSv31", "total": 7, "bidirectional": 6}], "cvss_bidirectional"),
            (
                "percentileCont",
                [{"malware_with_attribution": 50, "median_actors": 40.0, "max_actors": 90}],
                "attributed_to_fanout_plausible",
            ),
            (
                "n.edgeguard_managed IS NULL AND n.edgeguard_enriched IS NULL",
                [{"label": "Malware", "c": 3}],
                "ownership_marker_on_nodes",
            ),
        ],
    )
    def test_each_invariant_breaking_row_fails_its_check(self, vfb, monkeypatch, fragment, bad_rows, check):
        rep = _run(vfb, monkeypatch, override=lambda st, rows: bad_rows if fragment in st else rows)
        assert [c["check"] for c in rep.failed] == [check]

    def test_cve_properties_fail_when_analysed_cves_lack_them(self, vfb, monkeypatch):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [{"n": 5000, "cwe": 4600, "ref_tags": 80, "cpe_type": 90, "result_impacts": 4500}]
                if "AS result_impacts" in st
                else rows
            ),
        )
        assert [c["check"] for c in rep.failed] == ["cve_resilmesh_properties_present"]

    def test_edgeguard_edge_without_marker_fails(self, vfb, monkeypatch):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [{"type": "SOURCED_FROM", "c": 4}] if "r.edgeguard_managed IS NULL RETURN type(r)" in st else rows
            ),
        )
        assert [c["check"] for c in rep.failed] == ["ownership_marker_on_edges"]

    def test_mangled_entries_failure_names_the_manual_prerequisite(self, vfb, monkeypatch):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: [{"id": "S0005", "present": False}] if "OPTIONAL MATCH (t:Tool" in st else rows,
        )
        c = _check(rep, "mangled_attack_entries_present")
        assert c["ok"] is False and "Import Regexp" in c["detail"]["hint"]

    def test_relationship_without_sources_fails(self, vfb, monkeypatch):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [{"type": "USES_TECHNIQUE", "c": 1520714}] if "size(coalesce(r.sources, [])) = 0" in st else rows
            ),
        )
        assert [c["check"] for c in rep.failed] == ["relationships_name_their_source"]
        detail = _check(rep, "relationships_name_their_source")["detail"]
        assert detail["without_sources_by_type"] == [{"type": "USES_TECHNIQUE", "c": 1520714}]

    def test_provenance_scope_excludes_node_and_alert_edges(self, vfb, monkeypatch):
        seen = {}

        def capture(st, rows):
            if "size(coalesce(r.sources, [])) = 0" in st:
                seen["st"] = st
            return rows

        _run(vfb, monkeypatch, override=capture)
        assert "SOURCED_FROM" not in vfb.PROVENANCE_REL_TYPES and "INVOLVES" not in vfb.PROVENANCE_REL_TYPES
        assert "USES_TECHNIQUE" in vfb.PROVENANCE_REL_TYPES and "HAS_CVSS_v31" in vfb.PROVENANCE_REL_TYPES
        # 2026-10: campaign membership is PART_OF_CAMPAIGN; PART_OF is ResilMesh's asset hierarchy.
        assert "PART_OF_CAMPAIGN" in vfb.PROVENANCE_REL_TYPES and "PART_OF" not in vfb.PROVENANCE_REL_TYPES
        assert "$types" in seen["st"]

    def test_scalar_provenance_lists_fail(self, vfb, monkeypatch):
        # The 730-day graph of 2026-10-14: 21 ATTRIBUTED_TO edges with ``sources`` as a string
        # and 11 merged actors with ``zone`` as a string (APOC ``combine`` of equal values).
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [{"edges": 21}]
                if "apoc.meta.cypher.type(r.sources)" in st and "AS edges" in st
                else [{"nodes": 11}]
                if "apoc.meta.cypher.type(n.zone)" in st and "AS nodes" in st
                else rows
            ),
        )
        assert [c["check"] for c in rep.failed] == ["provenance_lists_are_lists"]
        assert _check(rep, "provenance_lists_are_lists")["detail"] == {"edges": 21, "nodes": 11}


# --------------------------------------------------------------------------- 2026-10 data contracts
def _replace_scan_row(rel_type, **changes):
    """Override for ``_run``: the per-type scan with one row changed (or added)."""

    def override(statement, rows):
        if "AS legacy_keys" not in statement:
            return rows
        out = [dict(r, **changes) if r["type"] == rel_type else r for r in rows]
        if not any(r["type"] == rel_type for r in rows):
            out.append(dict(_scan_row(rel_type), **changes))
        return out

    return override


class TestRelationshipProvenanceContract:
    """Relationship provenance (2026-10): each relationship type carries what its writers guarantee —
    the three lists and ``match_type`` on the evidence links, the lists only on the links the
    enrichment jobs derive, ``sources`` / ``misp_event_ids`` on the CVSS edges, and ``source`` /
    ``source_refs`` / ``misp_event_ids`` on the per-source ``SOURCED_FROM`` edge."""

    def test_correct_graph_passes_including_the_types_without_an_evidence_label(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch)
        c = _check(rep, "relationship_provenance_complete")
        assert c["ok"] is True and c["mandatory"] is True
        assert c["detail"]["missing_by_type"] == []
        # REFERS_TO carries no match_type, HAS_CVSS_* no source_refs, SOURCED_FROM no sources and only
        # the campaign links evidence_types: the healthy scan has them all at 0 and the check still passes.
        assert c["detail"]["edges_checked"] == 10 * len(_WRITTEN_BY_TYPE)

    def test_an_empty_misp_event_ids_list_is_reported_never_failed(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch, override=_replace_scan_row("PART_OF_CAMPAIGN", empty_misp_event_ids=10))
        c = _check(rep, "relationship_provenance_complete")
        assert c["ok"] is True
        assert {"type": "PART_OF_CAMPAIGN", "edges": 10} in c["detail"]["empty_misp_event_ids_by_type"]

    def test_edges_edgeguard_does_not_manage_are_not_judged(self, vfb, monkeypatch):
        # A partner's REFERS_TO without the marker: the ownership check owns that case.
        rep = _run(vfb, monkeypatch, override=_replace_scan_row("REFERS_TO", edges=14, managed=10))
        assert _check(rep, "relationship_provenance_complete")["ok"] is True

    @pytest.mark.parametrize(
        "rel_type, prop",
        [
            ("INDICATES", "match_type"),
            ("USES_TECHNIQUE", "match_type"),
            ("ATTRIBUTED_TO", "source_refs"),
            ("EXPLOITS", "misp_event_ids"),
            ("IN_TACTIC", "sources"),
            ("RUNS", "misp_event_ids"),
            ("PART_OF_CAMPAIGN", "source_refs"),
            # 2026-10-16: a campaign link that does not name the relationship types it rests on
            ("RUNS", "evidence_types"),
            ("PART_OF_CAMPAIGN", "evidence_types"),
            ("REFERS_TO", "sources"),
            ("HAS_CVSS_v31", "misp_event_ids"),
            ("SOURCED_FROM", "source"),
            ("SOURCED_FROM", "source_refs"),
            ("SOURCED_FROM", "misp_event_ids"),
        ],
    )
    def test_a_missing_contract_property_fails(self, vfb, monkeypatch, rel_type, prop):
        rep = _run(vfb, monkeypatch, override=_replace_scan_row(rel_type, **{f"with_{prop}": 7}))
        assert [c["check"] for c in rep.failed] == ["relationship_provenance_complete"]
        detail = _check(rep, "relationship_provenance_complete")["detail"]
        assert detail["missing_by_type"] == [{"type": rel_type, "property": prop, "edges": 3}]

    def test_a_list_valued_sourced_from_source_fails(self, vfb, monkeypatch):
        # ``with_source`` counts a string only: the scalar the alias-merge normaliser must leave alone.
        rep = _run(vfb, monkeypatch, override=_replace_scan_row("SOURCED_FROM", with_source=0))
        assert [c["check"] for c in rep.failed] == ["relationship_provenance_complete"]

    def test_informational_on_a_graph_without_edgeguard_edges(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch, override=lambda st, rows: [] if "AS legacy_keys" in st else rows)
        assert _check(rep, "relationship_provenance_complete")["ok"] is None

    def test_contract_covers_every_type_built_from_the_sources(self, vfb):
        assert set(vfb.REL_PROVENANCE_CONTRACT) == set(vfb.PROVENANCE_REL_TYPES) | {"SOURCED_FROM"}
        assert "INVOLVES" not in vfb.REL_PROVENANCE_CONTRACT and "PART_OF" not in vfb.REL_PROVENANCE_CONTRACT

    def test_one_pass_over_the_relationships_and_only_presence_is_judged(self, vfb):
        scan = vfb._REL_PROVENANCE_SCAN
        assert scan.count("MATCH ") == 1 and "RETURN type(r) AS type" in scan
        assert "r.misp_event_ids IS NOT NULL" in scan and "size(r.misp_event_ids)" not in scan
        assert "apoc.meta.cypher.type(r.source) WHEN 'STRING'" in scan

    def test_each_scan_column_counts_its_own_property_on_managed_edges(self, vfb):
        columns = {
            name: expr for expr, name in re.findall(r"sum\((CASE WHEN .*?END)\)\s+AS (\w+)", vfb._REL_PROVENANCE_SCAN)
        }
        for prop in ("sources", "source_refs", "misp_event_ids", "match_type", "evidence_types"):
            assert columns[f"with_{prop}"] == (
                f"CASE WHEN r.edgeguard_managed = true AND r.{prop} IS NOT NULL THEN 1 ELSE 0 END"
            ), prop
        assert columns["with_source"].startswith("CASE WHEN r.edgeguard_managed = true AND r.source IS NOT NULL THEN")
        assert columns["managed"] == "CASE WHEN r.edgeguard_managed = true THEN 1 ELSE 0 END"
        assert columns["empty_misp_event_ids"] == (
            "CASE WHEN r.edgeguard_managed = true AND r.misp_event_ids = [] THEN 1 ELSE 0 END"
        )
        # every column the check reads exists in the scan
        for props in vfb.REL_PROVENANCE_CONTRACT.values():
            assert {f"with_{p}" for p in props} <= set(columns)


# One relationship row for every group ``Neo4jClient.create_misp_relationships_batch`` writes
# (``exact`` marks a curated claim, written by its own exact-name query).
_ACTOR, _MALWARE, _IND = (
    ("ThreatActor", {"name": "apt29"}),
    ("Malware", {"name": "emotet"}),
    ("Indicator", {"value": "1.2.3.4"}),
)
_TECH, _CVE, _TOOL = (
    ("Technique", {"mitre_id": "T1059"}),
    ("CVE", {"cve_id": "CVE-2024-1"}),
    ("Tool", {"mitre_id": "S0002"}),
)
_SYNC_ROWS = [
    {
        "rel_type": rel_type,
        "from_type": src[0],
        "from_key": src[1],
        "to_type": dst[0],
        "to_key": dst[1],
        "match_type": "m",
        "source": "threatfox",
        "exact_names": exact,
    }
    for rel_type, src, dst, exact in (
        ("EMPLOYS_TECHNIQUE", _ACTOR, _TECH, False),
        ("EMPLOYS_TECHNIQUE", ("Campaign", {"name": "op x"}), _TECH, False),
        ("EMPLOYS_TECHNIQUE", _ACTOR, _TECH, True),
        ("IMPLEMENTS_TECHNIQUE", _MALWARE, _TECH, False),
        ("IMPLEMENTS_TECHNIQUE", _MALWARE, _TECH, True),
        ("IMPLEMENTS_TECHNIQUE", _TOOL, _TECH, False),
        ("ATTRIBUTED_TO", _MALWARE, ("ThreatActor", {"name": "ta542"}), False),
        ("INDICATES", _IND, _MALWARE, False),
        ("TARGETS", _IND, ("Sector", {"name": "energy"}), False),
        ("AFFECTS", _CVE, ("Sector", {"name": "energy"}), False),
        ("EXPLOITS", _IND, _CVE, False),
        ("EXPLOITS", _ACTOR, _CVE, False),
        ("EXPLOITS", _MALWARE, _CVE, False),
        ("USES_MALWARE", _ACTOR, _MALWARE, False),
        ("USES_TOOL", _ACTOR, _TOOL, False),
    )
]
_REL_MERGE = re.compile(r"MERGE \(\w+\)-\[(\w+):(\w+)\]->\(\w+\)")


class _Record(dict):
    """Every column reads 0; an APOC failure column read with ``get`` is absent (a clean batch)."""

    def __missing__(self, key):
        return 0


class _Result:
    def __init__(self, matched: int = 0):
        self.matched = matched

    def __iter__(self):
        return iter([{"name": "apt29"}])

    def single(self):
        # The curated templates return ``count(r)`` as ``matched``; every row of a batch matches here.
        return _Record(matched=self.matched)

    def consume(self):
        # 2026-10-16: the writers read every write result inside their ``try`` (the server reports an
        # execution error with it), so the double needs the method; nothing fails here, and the
        # summary reports one write so the batch counter inspection stays quiet.
        return SimpleNamespace(counters=SimpleNamespace(nodes_created=1))


class _RecordingSession:
    def __init__(self, queries):
        self.queries = queries

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, *args, **kwargs):
        self.queries.append(query)
        rows = kwargs.get("rows")
        return _Result(len(rows) if isinstance(rows, list) else 0)


class TestContractIsWhatTheWritersWrite:
    """The script's contract must equal what the writers of the baseline DAG put on each type:
    stricter fails a correct graph, looser misses a defect. Derived from the writers' own Cypher —
    every ``build_relationships`` step (rendered without a database), the sync's batch writer, the
    campaign and Vulnerability ↔ CVE jobs, the CVSS sub-node writer and the three ``SOURCED_FROM``
    writers. A property counts for a type when every writer of that type assigns it after its
    MERGE. The single-pair writers of the in-process ``run_pipeline.py`` path are not part of the
    baseline DAG and are left out."""

    def _writer_queries(self, monkeypatch) -> Dict[str, List[str]]:
        """The Cypher each writer sends, by writer, recorded without a database."""
        import build_relationships
        import enrichment_jobs
        from neo4j_client import Neo4jClient

        by_writer: Dict[str, List[str]] = defaultdict(list)

        class _BuildClient:
            def connect(self):
                return True

            def close(self):
                pass

            def run(self, query, **kw):
                return [{"count": 0, "c": 0}]

        def _batched(client, label, outer, inner, stats, key, batch_size=5000, skip_query=None, params=None):
            by_writer["build_relationships"].append(inner)
            return True

        monkeypatch.setattr(build_relationships, "Neo4jClient", _BuildClient)
        monkeypatch.setattr(build_relationships, "_safe_run_batched", _batched)
        monkeypatch.setattr(build_relationships, "query_pause", lambda: None)
        build_relationships.build_relationships()

        writer = ""
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        client.driver.session.side_effect = lambda **kw: _RecordingSession(by_writer[writer])
        client._connection_healthy = True
        writer = "sync"
        written = client.create_misp_relationships_batch([dict(r) for r in _SYNC_ROWS], source_id="misp")
        # every row reached its query (AFFECTS and the indicator EXPLOITS row run against two labels)
        assert (written, written.failed) == (len(_SYNC_ROWS) + 2, 0)
        writer = "enrichment"
        enrichment_jobs.build_campaign_nodes(client)
        enrichment_jobs.bridge_vulnerability_cve(client)
        writer = "cvss"
        for rel_type, label in (
            ("HAS_CVSS_v2", "CVSSv2"),
            ("HAS_CVSS_v30", "CVSSv30"),
            ("HAS_CVSS_v31", "CVSSv31"),
            ("HAS_CVSS_v40", "CVSSv40"),
        ):
            assert client._merge_cvss_node("CVE-2024-1", "nvd", label, rel_type, {"base_score": 7.5}, "13")
        writer = "sourced_from"
        key = {"value": "1.2.3.4", "indicator_type": "ipv4"}
        assert client._upsert_sourced_relationship("Indicator", key, "threatfox", "{}", 0.7, misp_event_id="13")
        client.merge_indicators_batch([dict(key, tag="threatfox", misp_event_id="13")], source_id="threatfox")
        client.merge_vulnerabilities_batch([{"cve_id": "CVE-2024-1", "tag": "nvd", "misp_event_id": "13"}], "nvd")
        return by_writer

    @staticmethod
    def _assignments(queries: List[str]) -> Dict[str, List[FrozenSet[str]]]:
        """Per relationship type, the contract properties each MERGE of that type assigns."""
        per_type: Dict[str, List[FrozenSet[str]]] = defaultdict(list)
        for query in queries:
            for merge in _REL_MERGE.finditer(query):
                var, rel_type = merge.groups()
                block = query[merge.end() :].split("MERGE (", 1)[0]
                per_type[rel_type].append(
                    frozenset(p for p in _SCAN_PROPS if re.search(rf"\b{re.escape(var)}\.{p}\s*=(?!=)", block))
                )
        return per_type

    def test_every_writer_path_was_recorded(self, monkeypatch):
        by_writer = self._writer_queries(monkeypatch)
        merged = {w: set(self._assignments(q)) for w, q in by_writer.items()}
        assert len(by_writer["build_relationships"]) == 20
        assert merged["build_relationships"] >= {"IN_TACTIC", "SUBTECHNIQUE_OF", "USES_TECHNIQUE", "TARGETS"}
        assert merged["sync"] == {
            "EMPLOYS_TECHNIQUE",
            "IMPLEMENTS_TECHNIQUE",
            "ATTRIBUTED_TO",
            "INDICATES",
            "TARGETS",
            "AFFECTS",
            "EXPLOITS",
            "USES_MALWARE",
            "USES_TOOL",
        }
        assert merged["enrichment"] == {"RUNS", "PART_OF_CAMPAIGN", "REFERS_TO"}
        assert merged["cvss"] == {"HAS_CVSS_v2", "HAS_CVSS_v30", "HAS_CVSS_v31", "HAS_CVSS_v40"}
        assert merged["sourced_from"] == {"SOURCED_FROM"}
        assert len(self._assignments(by_writer["sourced_from"])["SOURCED_FROM"]) == 3, "single + two batch writers"

    def test_contract_equals_what_every_writer_assigns(self, vfb, monkeypatch):
        per_type = self._assignments([q for queries in self._writer_queries(monkeypatch).values() for q in queries])
        guaranteed = {t: frozenset.intersection(*sets) for t, sets in per_type.items()}
        contract = {t: frozenset(props) for t, props in vfb.REL_PROVENANCE_CONTRACT.items()}
        assert set(contract) <= set(guaranteed), f"no writer found for {set(contract) - set(guaranteed)}"
        assert {t: guaranteed[t] for t in contract} == contract
        # The fixture the check tests run on is the same table.
        assert {t: guaranteed[t] for t in _WRITTEN_BY_TYPE} == _WRITTEN_BY_TYPE

    def test_every_relationship_row_of_the_sync_states_its_evidence(self):
        # ``match_type`` is assigned by the batch writer as ``coalesce(row.match_type, r.match_type)``:
        # it holds only because every row the sync builds names its evidence.
        import ast

        tree = ast.parse((_SRC / "run_misp_to_neo4j.py").read_text())
        rows = [
            {k.value for k in node.keys if isinstance(k, ast.Constant)}
            for node in ast.walk(tree)
            if isinstance(node, ast.Dict)
            and any(isinstance(k, ast.Constant) and k.value == "rel_type" for k in node.keys)
        ]
        assert len(rows) >= 12
        assert all("match_type" in keys for keys in rows)


class TestLegacyRelationshipProperties:
    """The keys dropped in 2026-10 (``source_id``, ``source_ids``, ``report_ids``) stay off EdgeGuard
    relationships; ``Source`` nodes keep ``source_id`` as their key."""

    def test_correct_graph_passes(self, vfb, monkeypatch):
        c = _check(_run(vfb, monkeypatch), "no_legacy_relationship_properties")
        assert c["ok"] is True and c["detail"]["source_nodes"] == len(_SOURCE_ROWS)

    @pytest.mark.parametrize("rel_type", ["INDICATES", "SOURCED_FROM", "HAS_CVSS_v31", "PART_OF"])
    def test_a_legacy_key_on_an_edgeguard_type_fails(self, vfb, monkeypatch, rel_type):
        rep = _run(vfb, monkeypatch, override=_replace_scan_row(rel_type, legacy_keys=4))
        assert [c["check"] for c in rep.failed] == ["no_legacy_relationship_properties"]
        assert {"type": rel_type, "edges": 4} in _check(rep, "no_legacy_relationship_properties")["detail"][
            "legacy_keys_by_type"
        ]

    def test_a_partner_type_is_reported_not_failed(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch, override=_replace_scan_row("ON", legacy_keys=2))
        c = _check(rep, "no_legacy_relationship_properties")
        assert c["ok"] is True and c["detail"]["legacy_keys_by_type"] == [{"type": "ON", "edges": 2}]

    def test_a_source_node_without_its_key_fails(self, vfb, monkeypatch):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                rows + [{"source_id": None, "sourced_from": 0}] if "AS sourced_from" in st else rows
            ),
        )
        assert [c["check"] for c in rep.failed] == ["no_legacy_relationship_properties"]
        assert _check(rep, "no_legacy_relationship_properties")["detail"]["source_nodes_without_source_id"] == 1

    def test_the_scan_reads_the_three_legacy_keys_on_every_relationship(self, vfb):
        scan = vfb._REL_PROVENANCE_SCAN
        assert scan.startswith("MATCH ()-[r]->() RETURN")
        for key in ("r.source_id IS NOT NULL", "r.source_ids IS NOT NULL", "r.report_ids IS NOT NULL"):
            assert key in scan


class TestEpssAndSsvc:
    """FIRST EPSS and CISA's SSVC on CVE nodes (2026-10): no EPSS on a graph with CVEs is a warning,
    never a failure (the job skips an unavailable feed); SSVC is reported."""

    def test_a_graph_with_epss_passes_and_the_check_is_never_mandatory(self, vfb, monkeypatch):
        c = _check(_run(vfb, monkeypatch), "cve_epss_and_ssvc")
        assert c["ok"] is True and c["mandatory"] is False
        assert c["detail"]["with_ssvc"] == 61000 and "hint" not in c["detail"]

    def test_cves_without_any_epss_are_a_warning(self, vfb, monkeypatch):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [dict(rows[0], with_epss=0, epss_score_dates=0, latest_epss_score_date=None)]
                if "AS ssvc_exploitation_active" in st
                else rows
            ),
        )
        assert [c["check"] for c in rep.warnings] == ["cve_epss_and_ssvc"] and rep.failed == []
        assert "EDGEGUARD_ENABLE_EPSS" in _check(rep, "cve_epss_and_ssvc")["detail"]["hint"]

    def test_informational_without_cves(self, vfb, monkeypatch):
        empty = {k: 0 for k in _EPSS_SSVC_ROW}
        rep = _run(vfb, monkeypatch, override=lambda st, rows: [empty] if "AS ssvc_exploitation_active" in st else rows)
        assert _check(rep, "cve_epss_and_ssvc")["ok"] is None and rep.warnings == []

    def test_query_shape(self, vfb, monkeypatch):
        seen = {}

        def capture(st, rows):
            if "AS ssvc_exploitation_active" in st:
                seen["st"] = st
            return rows

        _run(vfb, monkeypatch, override=capture)
        for fragment in (
            "MATCH (c:CVE)",
            "count(c.epss_score) AS with_epss",
            "count(DISTINCT c.epss_score_date)",
            "c.ssvc_technical_impact IS NOT NULL",
        ):
            assert fragment in seen["st"]


class TestAttributionFromSingleActorReports:
    """2026-10: an OTX pulse naming several actors attributes no malware (the aliases of one actor
    count as one), and a malware is part of a campaign only while attributed to its actor or
    (2026-10-16) used by it."""

    def test_a_correct_graph_passes_and_aliases_count_as_one_actor(self, vfb, monkeypatch):
        seen = {}

        def capture(st, rows):
            if "AS resting_on_several_actor_reports" in st:
                seen["st"] = st
            return rows

        monkeypatch.setattr(vfb, "_post", lambda st, params=None, timeout=180: _record(seen, st, params, capture))
        rep = vfb.run_checks(False, False)
        c = _check(rep, "attribution_from_single_actor_reports")
        assert c["ok"] is True and c["mandatory"] is True
        assert c["detail"]["reports_naming_several_actors"] == 2
        assert c["detail"]["pulses_marked_on_indicators"] == 2
        # Storm-2697 is The Gentlemen; the second pulse is marked on indicators only.
        assert seen["params"]["several"] == ["68cd617b3eb5b1212d11643d", "6a4fdf500b5e6dffde939998"]
        assert seen["params"]["feeds"] == ["alienvault_otx", "otx_pulse"]
        assert _check(rep, "campaign_malware_has_evidence")["ok"] is True

    def test_the_pulses_are_step_2ds_union_of_the_actor_nodes_and_the_indicator_marks(self, vfb, monkeypatch):
        """2026-10: the set is the one step 2d uses (``canonical_threat_actors.several_actor_reports``).
        A pulse marked only on indicators counts; a mark is the collector's judgement, taken as it is,
        while the pulses on the actor nodes are judged with the reference."""
        import canonical_threat_actors

        seen: dict = {}
        marks = ["6a189defc88ad66cd0a9d87d", " 6a4fdf500b5e6dffde939998 "]

        def marked(st, rows):
            if st == canonical_threat_actors.INDICATOR_MARKED_REPORTS_QUERY:
                seen["read"] = True
                return [{"pulses": marks, "indicators": 3}]
            return rows

        monkeypatch.setattr(vfb, "_post", lambda st, params=None, timeout=180: _record(seen, st, params, marked))
        rep = vfb.run_checks(False, False)
        assert seen["read"] is True
        # The alias pulse is not several on the actor nodes, but the collector marked it: it counts.
        assert seen["params"]["several"] == [
            "68cd617b3eb5b1212d11643d",
            "6a189defc88ad66cd0a9d87d",
            "6a4fdf500b5e6dffde939998",
        ]
        assert _check(rep, "attribution_from_single_actor_reports")["detail"]["pulses_marked_on_indicators"] == 2

    @pytest.mark.parametrize("column", ["resting_on_several_actor_reports", "naming_several_actor_reports"])
    def test_an_attribution_resting_on_or_naming_such_a_pulse_fails(self, vfb, monkeypatch, column):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [dict(rows[0], **{column: 70})] if "AS resting_on_several_actor_reports" in st else rows
            ),
        )
        assert [c["check"] for c in rep.failed] == ["attribution_from_single_actor_reports"]

    def test_without_the_reference_it_is_informational(self, vfb, monkeypatch):
        import canonical_threat_actors

        def unavailable(*_a, **_k):
            raise canonical_threat_actors.ReferenceUnavailable("test: not found")

        monkeypatch.setattr(vfb, "load_canonical_reference", unavailable)
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [dict(rows[0], resting_on_several_actor_reports=4)]
                if "AS resting_on_several_actor_reports" in st
                else rows
            ),
        )
        c = _check(rep, "attribution_from_single_actor_reports")
        assert c["ok"] is None and "unavailable" in c["detail"]["reference"] and rep.failed == []

    def test_a_malware_member_without_evidence_fails(self, vfb, monkeypatch):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: [dict(rows[0], without_evidence=3)] if "AS malware_links" in st else rows,
        )
        assert [c["check"] for c in rep.failed] == ["campaign_malware_has_evidence"]

    def test_no_pulse_recorded_on_any_actor_and_no_mark_is_informational(self, vfb, monkeypatch):
        # Nothing to judge: a pass would be vacuous.
        def unrecorded(marks):
            def override(st, rows):
                if "AS pid WITH pid, collect(DISTINCT a.name) AS names" in st:
                    return [{"reports": [], "pulses": 0}]
                if "UNWIND i.several_actor_pulses AS pid" in st:
                    return [{"pulses": marks, "indicators": len(marks)}]
                return rows

            return override

        rep = _run(vfb, monkeypatch, override=unrecorded([]))
        assert _check(rep, "attribution_from_single_actor_reports")["ok"] is None
        # 2026-10: the collector's marks alone are something to judge.
        rep = _run(vfb, monkeypatch, override=unrecorded(["6a4fdf500b5e6dffde939998"]))
        assert _check(rep, "attribution_from_single_actor_reports")["ok"] is True

    def test_no_same_pulse_attribution_is_informational(self, vfb, monkeypatch):
        # 2026-10: with no same-pulse ATTRIBUTED_TO at all the check passed as mandatory; there is nothing
        # to judge (a graph without OTX, or one whose attributions were all removed), as for 13c.
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [dict(rows[0], links=0, without_reports=0)] if "AS resting_on_several_actor_reports" in st else rows
            ),
        )
        c = _check(rep, "attribution_from_single_actor_reports")
        assert c["ok"] is None and c["mandatory"] is True and rep.failed == []
        assert c["detail"]["links"] == 0

    def test_no_malware_member_is_informational(self, vfb, monkeypatch):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [{"malware_links": 0, "without_evidence": 0}] if "AS malware_links" in st else rows
            ),
        )
        assert _check(rep, "campaign_malware_has_evidence")["ok"] is None

    def test_query_shape(self, vfb, monkeypatch):
        import canonical_threat_actors

        seen = {}

        def capture(st, rows):
            if "AS resting_on_several_actor_reports" in st:
                seen["attribution"] = st
            if "AS malware_links" in st:
                seen["campaign"] = st
            return rows

        _run(vfb, monkeypatch, override=capture)
        # The statement is shared with the Neo4j integration module, which runs it on a real graph.
        assert seen["attribution"] == canonical_threat_actors.ATTRIBUTION_CHECK_QUERY
        assert canonical_threat_actors.attribution_reports_cypher("r") in seen["attribution"]
        assert "WHERE r.match_type = 'otx_pulse' AND r.edgeguard_managed = true" in seen["attribution"]
        assert "THEN r.sources ELSE [r.sources] END WHERE s IN $feeds)" in seen["attribution"]
        # 2026-10-16: the membership check reads the builder's evidence definition: either link, each
        # in the direction its claim is made, between the member and the campaign's actor.
        import campaign_evidence

        assert seen["campaign"] == campaign_evidence.MALWARE_MEMBERSHIP_CHECK_QUERY
        assert "MATCH (a:ThreatActor {name: c.actor_name})" in seen["campaign"]
        assert "(a)<-[:ATTRIBUTED_TO]-(m)" in seen["campaign"] and "(a)-[:USES_MALWARE]->(m)" in seen["campaign"]


def _record(seen, statement, params, override):
    if "AS resting_on_several_actor_reports" in statement:
        seen["params"] = dict(params or {})
    rows = _healthy_rows(statement, params or {})
    return override(statement, rows)


class TestCampaignMembership:
    """Campaign membership is ``PART_OF_CAMPAIGN`` (Malware / Indicator → Campaign); ``PART_OF`` stays
    ResilMesh's (IP → Subnet, the OrganizationUnit hierarchy) and never ends at a Campaign."""

    def test_correct_graph_passes_and_resilmesh_part_of_is_left_alone(self, vfb, monkeypatch):
        assert _check(_run(vfb, monkeypatch), "campaign_membership_is_part_of_campaign")["ok"] is True
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: [dict(rows[0], part_of=40)] if "AS part_of_to_campaign" in st else rows,
        )
        assert _check(rep, "campaign_membership_is_part_of_campaign")["ok"] is True

    @pytest.mark.parametrize("column", ["part_of_to_campaign", "part_of_campaign_misplaced"])
    def test_campaign_membership_under_another_name_fails(self, vfb, monkeypatch, column):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: [dict(rows[0], **{column: 3})] if "AS part_of_to_campaign" in st else rows,
        )
        assert [c["check"] for c in rep.failed] == ["campaign_membership_is_part_of_campaign"]

    def test_query_shape(self, vfb, monkeypatch):
        seen = {}

        def capture(st, rows):
            if "AS part_of_to_campaign" in st:
                seen["st"] = st
            return rows

        _run(vfb, monkeypatch, override=capture)
        assert "COUNT { ()-[:PART_OF]->(:Campaign) }" in seen["st"]
        assert "WHERE NOT c:Campaign OR NOT (n:Malware OR n:Indicator)" in seen["st"]


class TestCampaignEvidence:
    """2026-10-16: no campaign without evidence. Every campaign EdgeGuard built rests on an
    ATTRIBUTED_TO or USES_MALWARE link of its actor and has that actor's RUNS; no RUNS comes from an
    actor that is not the campaign's or has neither link. Informational while there is no campaign."""

    def test_a_correct_graph_passes(self, vfb, monkeypatch):
        c = _check(_run(vfb, monkeypatch), "campaigns_have_evidence")
        assert c["ok"] is True and c["mandatory"] is True
        assert c["detail"] == _CAMPAIGN_EVIDENCE_ROW

    @pytest.mark.parametrize("column", ["without_evidence", "without_runs", "runs_without_evidence"])
    def test_each_defect_fails(self, vfb, monkeypatch, column):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: [dict(rows[0], **{column: 2})] if "AS runs_without_evidence" in st else rows,
        )
        assert [c["check"] for c in rep.failed] == ["campaigns_have_evidence"]

    def test_informational_without_campaigns(self, vfb, monkeypatch):
        empty = {k: 0 for k in _CAMPAIGN_EVIDENCE_ROW}
        rep = _run(vfb, monkeypatch, override=lambda st, rows: [empty] if "AS runs_without_evidence" in st else rows)
        assert _check(rep, "campaigns_have_evidence")["ok"] is None and rep.failed == []

    def test_a_runs_without_evidence_fails_without_edgeguard_campaigns(self, vfb, monkeypatch):
        """A RUNS left on a campaign EdgeGuard did not create (a partner's, or one written before), whose
        actor has no evidence, is a defect even when the graph holds no EdgeGuard campaign."""
        row = dict({k: 0 for k in _CAMPAIGN_EVIDENCE_ROW}, runs_without_evidence=1)
        rep = _run(vfb, monkeypatch, override=lambda st, rows: [row] if "AS runs_without_evidence" in st else rows)
        assert _check(rep, "campaigns_have_evidence")["ok"] is False
        assert [c["check"] for c in rep.failed] == ["campaigns_have_evidence"]

    def test_query_reads_the_builders_definition(self, vfb, monkeypatch):
        import campaign_evidence

        seen = {}

        def capture(st, rows):
            if "AS runs_without_evidence" in st:
                seen["st"] = st
            return rows

        _run(vfb, monkeypatch, override=capture)
        assert seen["st"] == campaign_evidence.CAMPAIGN_EVIDENCE_CHECK_QUERY
        # The campaigns EdgeGuard built; the actor by the campaign's name; either link; RUNS from it.
        assert "MATCH (c:Campaign) WHERE c.edgeguard_managed = true" in seen["st"]
        assert campaign_evidence.has_evidence("a") in seen["st"]
        assert "(:ThreatActor {name: c.actor_name})-[:RUNS]->(c)" in seen["st"]
        assert "coalesce(a.name = rc.actor_name, false)" in seen["st"]


class TestCveScoreFromCvss:
    """CVE scores (2026-10): with a CVSS sub-node whose base score is in [0, 10] the CVE has the
    selected sub-node's score and version and a CVSS rating; without one, no score, no version and
    severity UNKNOWN."""

    def test_correct_graph_passes(self, vfb, monkeypatch):
        c = _check(_run(vfb, monkeypatch), "cve_score_from_cvss")
        assert c["ok"] is True and c["mandatory"] is True

    @pytest.mark.parametrize("column", ["scored_without_score", "score_not_from_cvss", "unscored_with_score"])
    def test_each_kind_of_wrong_score_fails(self, vfb, monkeypatch, column):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: [dict(rows[0], **{column: 14451})] if "AS unscored_with_score" in st else rows,
        )
        assert [c["check"] for c in rep.failed] == ["cve_score_from_cvss"]

    def test_informational_without_cves(self, vfb, monkeypatch):
        empty = {"cves": 0, "with_cvss": None, "scored_without_score": None, "score_not_from_cvss": None}
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [dict(empty, unscored_with_score=None)] if "AS unscored_with_score" in st else rows
            ),
        )
        assert _check(rep, "cve_score_from_cvss")["ok"] is None and rep.failed == []

    def test_selection_is_the_writer_selection(self, vfb):
        import cvss_selection
        import neo4j_client

        assert vfb._CVSS_SELECTION_ORDER == tuple(
            (v.rel_type, v.label, v.version) for v in cvss_selection.CVSS_VERSIONS
        )
        assert vfb._CVSS_RATINGS == cvss_selection.QUALITATIVE_SEVERITIES

        def squeeze(text: str) -> str:
            return re.sub(r"\s+", "", text)

        assert squeeze("WITH c, " + vfb._CVE_BEST_CVSS) == squeeze(neo4j_client._cve_cvss_selection_cypher("c"))

    def test_query_judges_edgeguard_cves_against_unknown(self, vfb, monkeypatch):
        import cvss_selection

        seen = {}

        def capture(st, rows):
            if "AS unscored_with_score" in st:
                seen["st"] = st
            return rows

        _run(vfb, monkeypatch, override=capture)
        assert seen["st"].startswith("MATCH (c:CVE) WHERE c.edgeguard_managed = true WITH c, head(")
        assert f"coalesce(c.severity, '') <> '{cvss_selection.UNKNOWN_SEVERITY}'" in seen["st"]
        assert "c.cvss_score <> best[0].base_score OR c.cvss_version <> best[1]" in seen["st"]


class TestDefaultSourcesDelivered:
    """Per-source presence (2026-10): the ``SOURCED_FROM`` count of every ``Source`` node; a source
    collected by default that delivered nothing is a warning (exit code unchanged); keyed and
    flag-guarded sources are only listed."""

    def test_correct_graph_passes_and_lists_every_source_node(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch)
        c = _check(rep, "default_sources_delivered")
        assert c["ok"] is True and c["mandatory"] is False and rep.warnings == []
        assert c["detail"]["sourced_from_by_source"] == _SOURCE_ROWS
        assert c["detail"]["keyed_sources_without_data"] == ["virustotal"]
        assert c["detail"]["flag_guarded_sources_without_data"] == ["cisa_ics", "malwarebazaar"]

    @pytest.mark.parametrize("source", ["feodo_tracker", "nvd", "ssl_blacklist"])
    def test_a_silent_default_source_warns_without_failing(self, vfb, monkeypatch, source):
        def override(st, rows):
            if "AS sourced_from" in st:
                return [dict(x, sourced_from=0) if x["source_id"] == source else x for x in rows]
            return rows

        rep = _run(vfb, monkeypatch, override=override)
        c = _check(rep, "default_sources_delivered")
        assert c["ok"] is False and rep.failed == [] and [w["check"] for w in rep.warnings] == [c["check"]]
        assert c["detail"]["default_sources_without_data"] == [source]

    def test_a_missing_source_node_warns(self, vfb, monkeypatch):
        rep = _run(
            vfb,
            monkeypatch,
            override=lambda st, rows: (
                [x for x in rows if x["source_id"] != "cisa_kev"] if "AS sourced_from" in st else rows
            ),
        )
        assert _check(rep, "default_sources_delivered")["detail"]["default_sources_without_data"] == ["cisa_kev"]

    def test_a_keyed_source_without_data_is_not_a_warning(self, vfb, monkeypatch):
        def override(st, rows):
            if "AS sourced_from" in st:
                silent = ("threatfox", "urlhaus", "abuseipdb")
                return [dict(x, sourced_from=0) if x["source_id"] in silent else x for x in rows]
            return rows

        c = _check(_run(vfb, monkeypatch, override=override), "default_sources_delivered")
        assert c["ok"] is True
        assert c["detail"]["keyed_sources_without_data"] == ["virustotal", "threatfox", "urlhaus", "abuseipdb"]
        assert c["detail"]["default_sources_without_data"] == [], "URLhaus needs the abuse.ch key (THREATFOX_API_KEY)"

    def test_classification_follows_the_collectors_keys_and_flags(self, vfb):
        import collector_allowlist
        import source_key_check
        import source_registry

        def canonical(name: str) -> str:
            src = source_registry.get_source(name) or source_registry.get_source(name.split("_enrich")[0])
            assert src is not None, name
            return src.canonical_id

        collectors = {canonical(n) for n in collector_allowlist.COLLECT_SOURCES_CANONICAL}
        needs_key = [s for s in source_key_check.KEYED_SOURCES if s.needs_key]
        # A source behind its own flag stays flag-guarded when it also needs a key (MalwareBazaar uses
        # the abuse.ch key): its flag is off by default.
        primary = {canonical(s.name) for s in needs_key}
        flagged = {s for s in collectors - primary if not source_registry.get_source(s).cli_default_enabled}
        keyed = {canonical(name) for s in needs_key for name in s.sources} - flagged
        assert "urlhaus" in keyed, "the URLhaus export carries the abuse.ch key (THREATFOX_API_KEY)"
        assert set(vfb.KEYED_SOURCES) == keyed
        assert set(vfb.FLAG_GUARDED_SOURCES) == flagged == {"cisa_ics", "malwarebazaar"}
        assert set(vfb.DEFAULT_SOURCES) == collectors - keyed - flagged
        assert "nvd" in vfb.DEFAULT_SOURCES, "NVD needs no key (needs_key=False): it is collected by default"


class TestTlpCheckDescription:
    def test_the_check_says_where_lost_tags_show(self, vfb, monkeypatch):
        note = _check(_run(vfb, monkeypatch), "tlp_on_every_node")["detail"]["note"]
        assert "[TLP] MISP attribute" in note and "EDGEGUARD_DEFAULT_TLP" in note
        # the sync's own log line, so the note names a message that exists
        assert '"[TLP] MISP attribute %s has no tlp: tag' in (_SRC / "run_misp_to_neo4j.py").read_text()


class TestWarningLevel:
    """A warning is printed as WARN and in the RESULT line, keeps ``ok: false`` / ``mandatory: false`` in
    the JSON, and leaves the exit code at 0."""

    def _main(self, vfb, monkeypatch, capsys, argv, silent_source):
        def override(st, rows):
            if silent_source and "AS sourced_from" in st:
                return [dict(x, sourced_from=0) if x["source_id"] == silent_source else x for x in rows]
            return rows

        rep = _run(vfb, monkeypatch, override=override)
        monkeypatch.setattr(vfb, "run_checks", lambda *a, **k: rep)
        monkeypatch.setattr(sys, "argv", ["verify_fresh_baseline.py", *argv])
        code = vfb.main()
        return code, capsys.readouterr().out

    def test_text_output_with_a_warning(self, vfb, monkeypatch, capsys):
        code, out = self._main(vfb, monkeypatch, capsys, [], "feodo_tracker")
        assert code == 0
        assert "[WARN] default_sources_delivered:" in out
        assert "RESULT: PASS; 1 warning(s): default_sources_delivered" in out

    def test_text_output_without_a_warning(self, vfb, monkeypatch, capsys):
        code, out = self._main(vfb, monkeypatch, capsys, [], None)
        assert code == 0 and "[PASS] default_sources_delivered:" in out
        assert out.rstrip().endswith("RESULT: PASS")

    def test_a_failure_still_fails_next_to_a_warning(self, vfb, monkeypatch, capsys):
        def override(st, rows):
            if "AS sourced_from" in st:
                return [dict(x, sourced_from=0) if x["source_id"] == "feodo_tracker" else x for x in rows]
            if "AS part_of_to_campaign" in st:
                return [dict(rows[0], part_of_to_campaign=5)]
            return rows

        rep = _run(vfb, monkeypatch, override=override)
        monkeypatch.setattr(vfb, "run_checks", lambda *a, **k: rep)
        monkeypatch.setattr(sys, "argv", ["verify_fresh_baseline.py"])
        assert vfb.main() == 1
        out = capsys.readouterr().out
        assert "[FAIL] campaign_membership_is_part_of_campaign:" in out
        assert "RESULT: FAIL (1 mandatory check(s) failed); 1 warning(s): default_sources_delivered" in out

    def test_json_output(self, vfb, monkeypatch, capsys):
        code, out = self._main(vfb, monkeypatch, capsys, ["--json"], "feodo_tracker")
        result = json.loads(out)
        c = next(x for x in result["checks"] if x["check"] == "default_sources_delivered")
        assert code == 0 and result["passed"] is True and c["ok"] is False and c["mandatory"] is False


# --------------------------------------------------------------------------- 9b. revoked ATT&CK objects
def _run_with_graph(
    vfb,
    monkeypatch,
    techniques=_GRAPH_TECHNIQUES,
    actors=_GRAPH_ACTORS,
    software=_GRAPH_SOFTWARE,
    cited=_GRAPH_CITED,
    seen=None,
):
    """``run_checks`` on the healthy rows, with check 9b answered from ``techniques`` / ``actors`` /
    ``software`` / ``cited``."""

    def fake_post(statement, params=None, timeout=180):
        params = params or {}
        if seen is not None:
            seen.append((statement, params))
        if "AS recorded" in statement:
            return _cited_rows(cited)
        if "AS revoked_ids" in statement:
            return _revoked_technique_rows(params, techniques)
        if "AS revoked_groups_from_mitre" in statement:
            return _revoked_group_rows(params, actors)
        if "AS revoked_software" in statement:
            return _revoked_software_rows(params, software)
        return _healthy_rows(statement, params)

    monkeypatch.setattr(vfb, "_post", fake_post)
    return vfb.run_checks(False, False, False)


class TestRevokedAttackObjects:
    """Check 9b (2026-10): no Technique node carries an id the revoked-id map lists, no ThreatActor node
    from MITRE is a revoked group (mandatory); an actor another source named after a revoked group is a
    warning (the actor alias merge folds it into the successor). Judged with the committed map."""

    def test_a_correct_graph_passes(self, vfb, monkeypatch):
        rep = _run_with_graph(vfb, monkeypatch)
        for name in (
            "no_revoked_attack_techniques",
            "no_revoked_attack_groups",
            "revoked_group_names_folded",
            "no_revoked_attack_software",
            "translated_links_record_cited_ids",
        ):
            assert _check(rep, name)["ok"] is True, name
        assert rep.failed == [] and rep.warnings == []
        merges = _check(rep, "actor_merges_recorded")
        assert merges["ok"] is None and merges["detail"] == {"actors": 30, "names_folded": 33}

    def test_a_translated_link_without_its_cited_id_fails(self, vfb, monkeypatch):
        """The explainability write missing: links to successors exist, but some do not name the id."""
        rep = _run_with_graph(vfb, monkeypatch, cited=(25135, 24440, 24000))
        c = _check(rep, "translated_links_record_cited_ids")
        assert c["ok"] is False and c["mandatory"] is True
        assert [x["check"] for x in rep.failed] == ["translated_links_record_cited_ids"]

    def test_the_cited_ids_check_is_informational_without_translated_links(self, vfb, monkeypatch):
        rep = _run_with_graph(vfb, monkeypatch, cited=(0, 0, 0))
        assert _check(rep, "translated_links_record_cited_ids")["ok"] is None

    def test_the_cited_ids_check_receives_the_map(self, vfb, monkeypatch):
        import attack_revoked

        seen: List[Any] = []
        _run_with_graph(vfb, monkeypatch, seen=seen)
        ((statement, params),) = [(s, p) for s, p in seen if "AS recorded" in s]
        assert params["revoked"] == dict(attack_revoked.load_revoked_ids().techniques)
        assert "$revoked[toString(cited)]" in statement and "cited IN coalesce(r.cited_ids, [])" in statement

    def test_revoked_software_from_mitre_fails(self, vfb, monkeypatch):
        """The hosted graph of 2026-10-15: ``darkmoon`` from MITRE (revoked into PoisonIvy)."""
        rep = _run_with_graph(vfb, monkeypatch, software=_GRAPH_SOFTWARE + (("darkmoon", ("mitre_attck",)),))
        c = _check(rep, "no_revoked_attack_software")
        assert c["ok"] is False and c["mandatory"] is True and c["detail"]["examples"] == ["darkmoon"]
        assert [x["check"] for x in rep.failed] == ["no_revoked_attack_software"]

    def test_a_revoked_technique_node_fails(self, vfb, monkeypatch):
        rep = _run_with_graph(vfb, monkeypatch, techniques=_GRAPH_TECHNIQUES + ("T1086", "T1562.001"))
        c = _check(rep, "no_revoked_attack_techniques")
        assert c["ok"] is False and c["mandatory"] is True
        assert c["detail"]["revoked_ids"] == 2 and set(c["detail"]["examples"]) == {"T1086", "T1562.001"}
        assert [x["check"] for x in rep.failed] == ["no_revoked_attack_techniques"]

    def test_a_revoked_group_from_mitre_fails(self, vfb, monkeypatch):
        """The hosted graph of 2026-10-15: ``unc2452`` from MITRE (and OTX), 31 links."""
        actors = _GRAPH_ACTORS + (("unc2452", ("mitre_attck", "alienvault_otx")),)
        rep = _run_with_graph(vfb, monkeypatch, actors=actors)
        c = _check(rep, "no_revoked_attack_groups")
        assert c["ok"] is False and c["detail"]["revoked_groups_from_mitre"] == 1
        assert [x["check"] for x in rep.failed] == ["no_revoked_attack_groups"]

    def test_an_actor_another_source_named_after_a_revoked_group_is_a_warning(self, vfb, monkeypatch):
        actors = _GRAPH_ACTORS + (("charming kitten", ("alienvault_otx",)),)
        rep = _run_with_graph(vfb, monkeypatch, actors=actors)
        assert _check(rep, "no_revoked_attack_groups")["ok"] is True
        c = _check(rep, "revoked_group_names_folded")
        assert c["ok"] is False and c["mandatory"] is False
        assert c["detail"]["examples_other_sources"] == ["charming kitten"] and not c["detail"]["examples_from_mitre"]
        assert rep.failed == [] and [x["check"] for x in rep.warnings] == ["revoked_group_names_folded"]

    def test_informational_without_attack_data_rather_than_a_vacuous_pass(self, vfb, monkeypatch):
        rep = _run_with_graph(
            vfb,
            monkeypatch,
            techniques=(),
            actors=(("conti team", ("alienvault_otx",)),),
            software=(("darkmoon", ("alienvault_otx",)),),
        )
        for name in (
            "no_revoked_attack_techniques",
            "no_revoked_attack_groups",
            "revoked_group_names_folded",
            "no_revoked_attack_software",
        ):
            assert _check(rep, name)["ok"] is None, name

    def test_the_committed_map_is_what_the_check_asks_for(self, vfb, monkeypatch):
        import attack_revoked

        seen: List[Any] = []
        _run_with_graph(vfb, monkeypatch, seen=seen)
        (tech_stmt, tech_params), (group_stmt, group_params), (soft_stmt, soft_params) = [
            (s, p)
            for s, p in seen
            if "AS revoked_ids" in s or "AS revoked_groups_from_mitre" in s or "AS revoked_software" in s
        ]
        revoked = attack_revoked.load_revoked_ids()
        assert revoked.loaded and tech_params["ids"] == sorted(revoked.techniques)
        assert {"T1086", "T1562", "T1574.002"} <= set(tech_params["ids"])
        assert "t.mitre_id IN $ids" in tech_stmt and "count(t) AS techniques" in tech_stmt
        assert set(group_params["names"]) == {
            "apt34",
            "charming kitten",
            "dragonfly 2.0",
            "monsoon",
            "stolen pencil",
            "unc2452",
        }
        assert "toLower(trim(a.name)) IN $names" in group_stmt
        assert "'mitre_attck' IN coalesce(a.source, [])" in group_stmt
        # ngrok is left out: its successor (the tool ngrok) bears the same name
        assert soft_params["names"] == ["darkmoon"]
        assert "(n:Malware OR n:Tool) AND 'mitre_attck' IN coalesce(n.source, [])" in soft_stmt

    def test_an_unreadable_map_fails_the_checks(self, vfb, monkeypatch, tmp_path):
        import attack_revoked

        missing = tmp_path / "attack_revoked_ids.json"
        monkeypatch.setattr(vfb, "load_revoked_ids", lambda: attack_revoked.load_revoked_ids(missing))
        rep = _run_with_graph(vfb, monkeypatch)
        failed = {c["check"]: c["detail"] for c in rep.failed}
        assert set(failed) == {
            "no_revoked_attack_techniques",
            "no_revoked_attack_groups",
            "no_revoked_attack_software",
            "translated_links_record_cited_ids",
        }
        assert failed["no_revoked_attack_techniques"]["problem"] == "file not found"


class TestMalwareTwinsFolded:
    """Check 10a5 (2026-10): no Malware node from another source named after an ATT&CK software id
    ("cobalt strike - s0154", the MISP galaxy naming of OTX) remains when the MITRE Malware node of that
    id or base name exists. The decision is the enrichment job's (``plan_twin_folds``)."""

    @staticmethod
    def _run_with(vfb, monkeypatch, twins, seen=None, base_rows=()):
        def override(statement, rows):
            if seen is not None:
                seen.append(statement)
            if "b.name IN $bases" in statement:
                return [dict(b) for b in base_rows]
            return [dict(t) for t in twins] if "d.name =~ $suffixed" in statement else rows

        return _run(vfb, monkeypatch, override)

    def test_a_correct_graph_passes_and_reports_the_twin_without_a_target(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch)
        check = _check(rep, "malware_attack_twins_folded")
        assert check["ok"] is True
        assert check["detail"]["without_target"] == 1
        assert check["detail"]["examples_without_target"] == ["mimikatz - s0002"]

    def test_a_twin_without_a_mitre_node_beside_the_node_of_its_base_name_fails(self, vfb, monkeypatch):
        # A later pulse created "mimikatz": the job folds the twin into it (steps 9b / 2d link both).
        rep = self._run_with(
            vfb,
            monkeypatch,
            [dict(t) for t in _GRAPH_MALWARE_TWINS],
            base_rows=[{"name": "mimikatz", "aliases": ["Mimikatz - S0002"]}],
        )
        check = _check(rep, "malware_attack_twins_folded")
        assert check["ok"] is False and check["mandatory"] is True
        assert (check["detail"]["foldable_into_base_name"], check["detail"]["without_target"]) == (1, 0)
        assert check["detail"]["examples_foldable"] == ["mimikatz - s0002 -> mimikatz"]

    @pytest.mark.parametrize(
        "twin, target",
        [
            ({"name": "cobalt strike - s0154", "aliases": []}, "cobalt strike"),  # by the id MITRE delivered
            ({"name": "agent tesla - s0331", "aliases": []}, "agent tesla"),  # by base name, id unreadable
            ({"name": "darkmoon - s0209", "aliases": []}, "poisonivy"),  # a revoked id, by its successor
            ({"name": "cs beacon", "aliases": ["CS Beacon - S0154"]}, "cobalt strike"),  # an alias of its own name
        ],
    )
    def test_a_twin_the_job_folds_fails(self, vfb, monkeypatch, twin, target):
        rep = self._run_with(vfb, monkeypatch, [twin])
        check = _check(rep, "malware_attack_twins_folded")
        assert check["ok"] is False and check["mandatory"] is True
        assert check["detail"]["examples_foldable"] == [f"{twin['name']} -> {target}"]

    def test_an_ambiguous_twin_fails(self, vfb, monkeypatch):
        # Its id names one MITRE node and its base name another (whose id cannot be read).
        rep = self._run_with(vfb, monkeypatch, [{"name": "agent tesla - s0154", "aliases": []}])
        check = _check(rep, "malware_attack_twins_folded")
        assert check["ok"] is False and check["detail"]["ambiguous"] == 1

    def test_informational_without_a_suffixed_name_and_no_second_read(self, vfb, monkeypatch):
        seen: List[str] = []
        rep = self._run_with(vfb, monkeypatch, [], seen=seen)
        assert _check(rep, "malware_attack_twins_folded")["ok"] is None
        assert not any("AS attack_raw" in st for st in seen)

    def test_query_shape(self, vfb, monkeypatch):
        from attack_software_names import (
            CYPHER_BASE_NODES_READ,
            CYPHER_FOLDED_FAMILIES_READ,
            CYPHER_SOFTWARE_ID_SUFFIX,
            CYPHER_SUFFIXED_NAME,
            cypher_family_name_variants,
        )

        seen: List[Any] = []

        def fake_post(statement, params=None, timeout=180):
            seen.append((statement, params or {}))
            return _healthy_rows(statement, params or {})

        monkeypatch.setattr(vfb, "_post", fake_post)
        vfb.run_checks(False, False)
        ((twin_st, twin_params),) = [(st, p) for st, p in seen if "d.name =~ $suffixed" in st]
        assert twin_params == {"suffixed": CYPHER_SUFFIXED_NAME}
        assert "NOT 'mitre_attck' IN coalesce(d.source, [])" in twin_st
        ((attack_st, _p),) = [(st, p) for st, p in seen if "AS attack_raw" in st]
        assert "(c)-[sf:SOURCED_FROM]->(:Source {source_id: 'mitre_attck'})" in attack_st
        ((_base_st, base_params),) = [(st, p) for st, p in seen if st == CYPHER_BASE_NODES_READ]
        assert base_params == {"bases": ["mimikatz"], "mitre_source": "mitre_attck"}
        # Check 10a4 looks a family up as step 9b does: as given and without the ATT&CK software id,
        # each through the names the twin merge folded (the same expression, the same map).
        ((_folded_st, folded_params),) = [(st, p) for st, p in seen if st == CYPHER_FOLDED_FAMILIES_READ]
        assert folded_params == {"mitre_source": "mitre_attck"}
        ((pulse_st, pulse_params),) = [(st, p) for st, p in seen if "pulse_malware_families" in st]
        assert pulse_params == {
            "software_id_suffix": CYPHER_SOFTWARE_ID_SUFFIX,
            "folded_families": {"agenttesla": "agent tesla", "cobalt strike - s0154": "cobalt strike"},
        }
        assert "OPTIONAL MATCH (m:Malware) WHERE m.name IN " + cypher_family_name_variants("f") + " " in pulse_st


# --------------------------------------------------------------------------- 10d-10j. sector evidence
class TestSectorEvidence:
    """2026-10-16: a link to a Sector names only the feeds whose SOURCED_FROM zones give its sector, its
    confidence is the table's value of its label, and ``advisory_sector`` (CISA's ICS statement) sits on
    AFFECTS links to sectors CISA stated, and on every one of them. A graph without per-source zones
    (built before) is not judged: the checks report instead of passing vacuously."""

    # A graph with CISA ICS: the 2026-10-16 hosted figures (energy 2,052, finance 955, healthcare 1,119;
    # 4,164 CISA ICS records, 1,978 of them with no tracked sector).
    @staticmethod
    def _cisa_graph(st, rows):
        if "AS with_stated_zones" in st:
            return [
                {
                    "edges": 380000,
                    "with_zones": 380000,
                    "with_stated_zones": 2186,
                    "with_stated_refs": 2186,
                    "stating_feed_edges_with_stated_refs": 2186,
                }
            ]
        if "AS cisa_global" in st:
            return [{"cisa_records": 4164, "cisa_global": 1978, "without_zones": 0}]
        if "AS advisory_links" in st:
            return [{"advisory_links": 4126, "misplaced": 0, "examples": []}]
        if "AS not_labelled" in st:
            return [{"stated": 4126, "not_labelled": 0, "examples": []}]
        if "AS other_confidence" in st:
            return [
                {"label": "advisory_sector", "links": 4126, "other_confidence": 0},
                {"label": "zone_classification", "links": 68400, "other_confidence": 0},
            ]
        return rows

    def test_a_correct_default_graph_passes_and_reports(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch)
        assert _check(rep, "sector_links_name_only_feeds_that_gave_the_sector")["ok"] is True
        assert _check(rep, "sector_confidence_follows_label")["ok"] is True
        # no CISA ICS on a default graph: nothing to judge, not a vacuous pass
        assert _check(rep, "advisory_sector_only_where_cisa_stated")["ok"] is None
        assert _check(rep, "cisa_stated_sectors_linked_as_advisory_sector")["ok"] is None
        for name in ("sector_evidence_breakdown", "cisa_ics_contribution", "node_sectors_without_a_feed"):
            assert _check(rep, name)["ok"] is None and _check(rep, name)["mandatory"] is True
        assert _check(rep, "sector_evidence_breakdown")["detail"] == _SECTOR_BREAKDOWN_ROWS

    def test_a_graph_with_cisa_ics_passes_with_the_flag(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch, override=self._cisa_graph, require_cisa_ics=True)
        for name in (
            "sector_links_name_only_feeds_that_gave_the_sector",
            "advisory_sector_only_where_cisa_stated",
            "cisa_stated_sectors_linked_as_advisory_sector",
            "sector_links_cite_only_records_that_gave_the_sector",
            "sector_confidence_follows_label",
        ):
            assert _check(rep, name)["ok"] is True, name

    def test_a_link_naming_a_feed_that_did_not_give_the_sector_fails(self, vfb, monkeypatch):
        # The 2026-10-16 hosted graph: NVD energy guesses on CVEs CISA left global named cisa_ics.
        wrong = [{"type": "AFFECTS", "label": "CVE", "source": "cisa_ics", "c": 420}]

        def override(st, rows):
            return wrong if "NOT s.name IN" in st else rows

        rep = _run(vfb, monkeypatch, override=override)
        assert [c["check"] for c in rep.failed] == ["sector_links_name_only_feeds_that_gave_the_sector"]
        assert (
            _check(rep, "sector_links_name_only_feeds_that_gave_the_sector")["detail"][
                "naming_a_feed_that_did_not_give_the_sector"
            ]
            == wrong
        )

    def test_a_graph_without_per_source_zones_is_not_judged(self, vfb, monkeypatch):
        def override(st, rows):
            if "AS with_stated_zones" in st:
                return [{"edges": 374342, "with_zones": 0, "with_stated_zones": 0}]
            return rows

        rep = _run(vfb, monkeypatch, override=override)
        assert _check(rep, "sector_links_name_only_feeds_that_gave_the_sector")["ok"] is None

    def test_advisory_sector_outside_a_cisa_statement_fails(self, vfb, monkeypatch):
        def override(st, rows):
            if "AS advisory_links" in st:
                return [{"advisory_links": 4127, "misplaced": 1, "examples": ["TARGETS Indicator -> energy"]}]
            return self._cisa_graph(st, rows)

        rep = _run(vfb, monkeypatch, override=override)
        assert [c["check"] for c in rep.failed] == ["advisory_sector_only_where_cisa_stated"]

    def test_a_stated_sector_not_labelled_advisory_sector_fails(self, vfb, monkeypatch):
        def override(st, rows):
            if "AS not_labelled" in st:
                return [{"stated": 4126, "not_labelled": 3, "examples": ["CVE-2025-7639 energy"]}]
            return self._cisa_graph(st, rows)

        rep = _run(vfb, monkeypatch, override=override)
        assert [c["check"] for c in rep.failed] == ["cisa_stated_sectors_linked_as_advisory_sector"]

    def test_cisa_ics_records_without_zones_are_not_judged(self, vfb, monkeypatch):
        """The hosted graph of 2026-10-14/16: 4,164 CISA ICS records, none with ``zones`` or
        ``stated_zones`` (written before 2026-10-16; on a kept graph unchanged attributes are not re-read).
        No record can state a sector, so ``--require-cisa-ics`` does not fail the stated-sector check by
        construction."""

        def override(st, rows):
            if "AS with_stated_zones" in st:
                return [{"edges": 374342, "with_zones": 0, "with_stated_zones": 0, "with_stated_refs": 0}]
            if "AS cisa_global" in st:
                return [{"cisa_records": 4164, "cisa_global": 0, "without_zones": 4164}]
            if "AS not_labelled" in st:
                return [{"stated": 0, "not_labelled": 0, "examples": []}]
            if "OPTIONAL MATCH (s:Source {source_id: 'cisa_ics'})" in st:
                return [{"present": True, "edges": 4164}]
            return rows

        rep = _run(vfb, monkeypatch, override=override, require_cisa_ics=True)
        assert _check(rep, "cisa_ics_source_present")["ok"] is True
        check = _check(rep, "cisa_stated_sectors_linked_as_advisory_sector")
        assert check["ok"] is None and check["detail"]["cisa_records_with_zones"] == 0
        assert "cisa_stated_sectors_linked_as_advisory_sector" not in {c["check"] for c in rep.failed}

    def test_cisa_ics_records_with_zones_but_no_statement(self, vfb, monkeypatch):
        """CISA ICS records written by the current code (``zones`` set) and still no stated sector: with
        ``--require-cisa-ics`` that fails."""

        def override(st, rows):
            if "AS cisa_global" in st:
                return [{"cisa_records": 12, "cisa_global": 0, "without_zones": 0}]
            if "AS not_labelled" in st:
                return [{"stated": 0, "not_labelled": 0, "examples": []}]
            return rows

        rep = _run(vfb, monkeypatch, override=override, require_cisa_ics=True)
        assert _check(rep, "cisa_stated_sectors_linked_as_advisory_sector")["ok"] is False

    def test_a_sector_link_citing_an_advisory_of_another_sector_fails(self, vfb, monkeypatch):
        """CVE-2026-32645: ICSA-26-281-01 names Energy, ICSMA-26-283-01 names Healthcare; a healthcare link
        that cites ICSA-26-281-01 sends a STIX reader to an advisory that does not name Healthcare."""
        wrong = [
            {
                "type": "AFFECTS",
                "source": "cisa_ics",
                "c": 1,
                "examples": ["healthcare cisa_ics:ICSA-26-281-01"],
            }
        ]

        def override(st, rows):
            if "] AS other RETURN" in st:
                return wrong
            return self._cisa_graph(st, rows)

        rep = _run(vfb, monkeypatch, override=override)
        assert [c["check"] for c in rep.failed] == ["sector_links_cite_only_records_that_gave_the_sector"]
        detail = _check(rep, "sector_links_cite_only_records_that_gave_the_sector")["detail"]
        assert detail["citing_a_record_of_another_sector"] == wrong

    def test_no_per_sector_references_is_not_judged(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch)
        assert _check(rep, "sector_links_cite_only_records_that_gave_the_sector")["ok"] is None

    def test_a_confidence_other_than_the_labels_fails(self, vfb, monkeypatch):
        # The old graph: zone_classification links at 1.0
        def override(st, rows):
            if "AS other_confidence" in st:
                return [{"label": "zone_classification", "links": 72500, "other_confidence": 270000}]
            return rows

        rep = _run(vfb, monkeypatch, override=override)
        assert [c["check"] for c in rep.failed] == ["sector_confidence_follows_label"]

    def test_no_sector_link_is_not_judged(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch, override=lambda st, rows: [] if "AS other_confidence" in st else rows)
        assert _check(rep, "sector_confidence_follows_label")["ok"] is None

    def test_queries_read_the_table_and_the_per_source_zones(self, vfb, monkeypatch):
        seen: Dict[str, Any] = {}

        def capture(st, rows):
            for key in ("AS other_confidence", "NOT s.name IN", "zone_name AS sector", "AS advisory_links"):
                if key in st:
                    seen[key] = st
            return rows

        def fake_post(statement, params=None, timeout=180):
            if "AS other_confidence" in statement:
                seen["params"] = params
            if "] AS other RETURN" in statement:
                seen["other"] = (statement, params)
            return capture(statement, _healthy_rows(statement, params or {}))

        monkeypatch.setattr(vfb, "_post", fake_post)
        vfb.run_checks(False, False, False)
        assert seen["params"] == {
            "labels": ["advisory_sector", "otx_industries", "zone_classification"],
            "conf": {"zone_classification": 0.5, "otx_industries": 0.6, "advisory_sector": 0.9},
        }
        assert "MATCH (n)-[sf:SOURCED_FROM]->(:Source {source_id: f})" in seen["NOT s.name IN"]
        assert "WHERE sf.zones IS NOT NULL" in seen["NOT s.name IN"]
        # the node sectors no feed gave are counted with the rule of build_relationships steps 7a-7d
        assert "WHERE size(_feeds) = 0" in seen["zone_name AS sector"]
        assert "type(r) = 'AFFECTS' AND s:Sector AND (n:CVE OR n:Vulnerability)" in seen["AS advisory_links"]
        assert "sf.stated_zones" in seen["AS advisory_links"]
        # the records of a sector are read with the writer's format, "<zone>|<source>:<id>"
        other, params = seen["other"]
        # judged only for the feeds whose records state every zone they give (2026-10-18)
        assert params == {"sep": "|", "ref_sep": ":", "stating_feeds": ["cisa_ics"]}
        assert "STARTS WITH s.name + $sep" in other and "STARTS WITH src.source_id + $ref_sep" in other
        assert "src.source_id IN $stating_feeds" in other


# --------------------------------------------------------------------------- 10k-10m. OTX industries
class TestOtxIndustriesLabel:
    """2026-10-18: an OTX report's own industries are the statement ``otx_industries`` (0.6) on TARGETS
    links from an Indicator, ThreatActor or Malware to the sectors they map to. The label sits only on
    such a link to a sector an OTX record stated (the alienvault_otx ``SOURCED_FROM`` ``stated_zones``),
    never on AFFECTS; the link cites a report that stated it; every stated sector is linked so. Check 10k
    judges only the feeds whose records state every zone they give: an OTX record also gives zones by
    keyword, which its per-sector references do not record."""

    # A graph after a baseline with the 2026-10-18 code: 41,200 OTX statements (figures illustrative).
    @staticmethod
    def _otx_graph(st, rows):
        if "AS otx_links" in st:
            return [
                {"otx_links": 41200, "on_affects": 0, "misplaced": 0, "citing_no_stating_report": 0, "examples": []}
            ]
        if "AS otx_not_labelled" in st:
            return [{"stated": 41200, "otx_not_labelled": 0, "examples": []}]
        if "AS other_confidence" in st:
            return [
                {"label": "otx_industries", "links": 41200, "other_confidence": 0},
                {"label": "zone_classification", "links": 31300, "other_confidence": 0},
            ]
        if "AS with_stated_zones" in st:
            # stated_refs on OTX edges only: none of a feed that states every zone
            return [
                {
                    "edges": 380000,
                    "with_zones": 380000,
                    "with_stated_zones": 40100,
                    "with_stated_refs": 40100,
                    "stating_feed_edges_with_stated_refs": 0,
                }
            ]
        return rows

    def test_a_default_graph_without_statements_is_not_judged(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch)
        assert _check(rep, "otx_industries_only_where_otx_stated")["ok"] is None
        assert _check(rep, "otx_stated_sectors_linked_as_otx_industries")["ok"] is None
        assert _check(rep, "sector_links_by_evidence_label")["detail"] == _SECTOR_LABEL_COUNT_ROWS

    def test_a_graph_with_otx_statements_passes(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch, override=self._otx_graph)
        assert rep.failed == [], [c["check"] for c in rep.failed]
        for name in (
            "otx_industries_only_where_otx_stated",
            "otx_stated_sectors_linked_as_otx_industries",
            "sector_confidence_follows_label",
        ):
            assert _check(rep, name)["ok"] is True, name
        # OTX's per-sector references are no judgement of 10k: reported, not a vacuous pass
        assert _check(rep, "sector_links_cite_only_records_that_gave_the_sector")["ok"] is None

    @pytest.mark.parametrize(
        "row",
        [
            # on a sector no OTX record stated
            {"otx_links": 41201, "on_affects": 0, "misplaced": 1, "citing_no_stating_report": 0},
            # on AFFECTS: a targeted industry is no deployment statement
            {"otx_links": 41201, "on_affects": 1, "misplaced": 1, "citing_no_stating_report": 0},
            # a stated link that cites none of the reports that stated its sector
            {"otx_links": 41200, "on_affects": 0, "misplaced": 0, "citing_no_stating_report": 2},
        ],
    )
    def test_a_misplaced_label_fails(self, vfb, monkeypatch, row):
        def override(st, rows):
            if "AS otx_links" in st:
                return [dict(row, examples=["AFFECTS CVE -> energy"])]
            return self._otx_graph(st, rows)

        rep = _run(vfb, monkeypatch, override=override)
        assert [c["check"] for c in rep.failed] == ["otx_industries_only_where_otx_stated"]

    def test_a_stated_sector_not_labelled_otx_industries_fails(self, vfb, monkeypatch):
        def override(st, rows):
            if "AS otx_not_labelled" in st:
                return [{"stated": 41200, "otx_not_labelled": 7, "examples": ["Malware examplelocker energy"]}]
            return self._otx_graph(st, rows)

        rep = _run(vfb, monkeypatch, override=override)
        assert [c["check"] for c in rep.failed] == ["otx_stated_sectors_linked_as_otx_industries"]

    def test_a_link_citing_none_of_its_stating_reports_is_named(self, vfb, monkeypatch):
        """A stated link that cites none of the pulses its sector's ``stated_refs`` record fails with the
        node and sector to trace (``citing_examples``), not with an empty example list."""

        def override(st, rows):
            if "AS otx_links" in st:
                assert "AS citing_examples" in st
                return [
                    {
                        "otx_links": 41200,
                        "on_affects": 0,
                        "misplaced": 0,
                        "citing_no_stating_report": 1,
                        "examples": [],
                        "citing_examples": ["Indicator 198.51.100.23 -> energy"],
                    }
                ]
            return self._otx_graph(st, rows)

        rep = _run(vfb, monkeypatch, override=override)
        check = _check(rep, "otx_industries_only_where_otx_stated")
        assert check["ok"] is False and check["detail"]["citing_examples"] == ["Indicator 198.51.100.23 -> energy"]

    def test_the_citing_examples_name_the_links_the_count_counts(self, vfb, monkeypatch):
        seen: Dict[str, str] = {}

        def fake_post(statement, params=None, timeout=180):
            if "AS otx_links" in statement:
                seen["links"] = statement
            return _healthy_rows(statement, params or {})

        monkeypatch.setattr(vfb, "_post", fake_post)
        vfb.run_checks(False, False, False)
        counted, examples = seen["links"].split("AS citing_no_stating_report", 1)
        condition = "stated AND size(stating_refs) > 0 AND NONE(_x IN stating_refs WHERE _x IN "
        assert condition in counted and condition in examples.split("AS citing_examples", 1)[0]

    def test_require_otx_industries_fails_when_otx_records_give_sectors_but_state_none(self, vfb, monkeypatch):
        """A run that lost the pulses' industries before the sync (a regression in MISPWriter or the parser)
        leaves a graph without statements, which the two OTX checks do not judge. With
        ``--require-otx-industries`` the stated-sector check fails once OTX records give a sector."""
        rep = _run(vfb, monkeypatch)
        assert _check(rep, "otx_stated_sectors_linked_as_otx_industries")["ok"] is None
        rep = _run(vfb, monkeypatch, require_otx_industries=True)
        assert [c["check"] for c in rep.failed] == ["otx_stated_sectors_linked_as_otx_industries"]
        detail = _check(rep, "otx_stated_sectors_linked_as_otx_industries")["detail"]
        assert detail["otx_records_with_a_sector"] == 54250 and detail["otx_records_stating"] == 0

    @pytest.mark.parametrize(
        "records",
        [
            # no OTX record gives a sector (OTX off, or a graph written before the per-source zones)
            {"otx_records": 0, "otx_records_with_a_sector": 0, "otx_records_stating": 0},
            {"otx_records": 148000, "otx_records_with_a_sector": 0, "otx_records_stating": 0},
        ],
    )
    def test_require_otx_industries_does_not_judge_without_an_otx_sector(self, vfb, monkeypatch, records):
        def override(st, rows):
            if "AS otx_records_with_a_sector" in st:
                return [dict(records)]
            return rows

        rep = _run(vfb, monkeypatch, override=override, require_otx_industries=True)
        assert _check(rep, "otx_stated_sectors_linked_as_otx_industries")["ok"] is None
        assert rep.failed == []

    def test_require_otx_industries_passes_a_graph_with_statements(self, vfb, monkeypatch):
        def override(st, rows):
            if "AS otx_records_with_a_sector" in st:
                return [{"otx_records": 148000, "otx_records_with_a_sector": 54250, "otx_records_stating": 40100}]
            return self._otx_graph(st, rows)

        rep = _run(vfb, monkeypatch, override=override, require_otx_industries=True)
        assert rep.failed == [] and _check(rep, "otx_stated_sectors_linked_as_otx_industries")["ok"] is True

    def test_queries_read_the_table(self, vfb, monkeypatch):
        seen: Dict[str, Any] = {}

        def fake_post(statement, params=None, timeout=180):
            for key in ("AS otx_links", "AS otx_not_labelled", "AS with_stated_zones", "AS otx_records_with_a_sector"):
                if key in statement:
                    seen[key] = (statement, params)
            return _healthy_rows(statement, params or {})

        monkeypatch.setattr(vfb, "_post", fake_post)
        vfb.run_checks(False, False, False)
        links, params = seen["AS otx_links"]
        assert params == {"label": "otx_industries", "feeds": ["alienvault_otx"], "sep": "|"}
        assert "type(r) = 'TARGETS' AND s:Sector AND (n:Indicator OR n:ThreatActor OR n:Malware)" in links
        assert "sf.stated_zones" in links and "sf.stated_refs" in links and "r.source_refs" in links
        stated, params = seen["AS otx_not_labelled"]
        assert params == {
            "label": "otx_industries",
            "feeds": ["alienvault_otx"],
            "labels": ["advisory_sector", "otx_industries", "zone_classification"],
        }
        assert "(n:Indicator OR n:ThreatActor OR n:Malware)" in stated and "OPTIONAL MATCH (n)-[r:TARGETS]->" in stated
        zoned, params = seen["AS with_stated_zones"]
        assert params == {"stating_feeds": ["cisa_ics"]}
        records, params = seen["AS otx_records_with_a_sector"]
        assert params == {"feeds": ["alienvault_otx"]}
        assert "(n:Indicator OR n:ThreatActor OR n:Malware)" in records and "_z <> 'global'" in records


# --------------------------------------------------------------------------- 16. descriptions and aging
class TestRankedDescriptionsAndAging:
    """2026-10-16: every ranked description names its source and every Indicator has an aging basis and a
    source confidence; both are judged whenever the graph holds such nodes."""

    def test_a_correct_graph_passes(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch)
        assert _check(rep, "descriptions_name_their_source")["ok"] is True
        assert _check(rep, "indicators_have_aging_basis")["ok"] is True

    def test_a_description_without_its_source_fails(self, vfb, monkeypatch):
        def override(st, rows):
            if "AS without_source," in st:
                return [{"described": 860, "without_source": 859, "example_labels": ["ThreatActor"]}]
            return rows

        rep = _run(vfb, monkeypatch, override=override)
        assert [c["check"] for c in rep.failed] == ["descriptions_name_their_source"]
        assert _check(rep, "descriptions_name_their_source")["detail"]["without_source"] == 859

    @pytest.mark.parametrize("missing", ["without_aging_basis", "without_source_confidence"])
    def test_an_indicator_without_aging_fails(self, vfb, monkeypatch, missing):
        def override(st, rows):
            if "AS without_aging_basis" in st:
                return [dict(_AGING_ROW, **{missing: 217247})]
            return rows

        rep = _run(vfb, monkeypatch, override=override)
        assert [c["check"] for c in rep.failed] == ["indicators_have_aging_basis"]

    def test_an_empty_graph_is_not_judged(self, vfb, monkeypatch):
        def override(st, rows):
            if "AS without_source," in st:
                return [{"described": 0, "without_source": 0, "example_labels": []}]
            if "AS without_aging_basis" in st:
                return [{"indicators": 0, "without_aging_basis": 0, "without_source_confidence": 0}]
            return rows

        rep = _run(vfb, monkeypatch, override=override)
        assert _check(rep, "descriptions_name_their_source")["ok"] is None
        assert _check(rep, "indicators_have_aging_basis")["ok"] is None

    def test_the_labels_come_from_the_description_ranking(self, vfb):
        from description_ranking import ranking_for_label

        assert set(vfb._RANKED_DESCRIPTION_LABELS) == {
            "CVE",
            "Vulnerability",
            "Malware",
            "ThreatActor",
            "Tool",
            "Technique",
            "Tactic",
        }
        assert all(ranking_for_label(label) for label in vfb._RANKED_DESCRIPTION_LABELS)

    def test_the_cli_judges_every_graph_alike(self, vfb, monkeypatch, capsys):
        """The CLI passes only the four ``--require-*`` flags; there is no option that reports instead of
        judging the description-source, aging or stated-sector checks."""
        seen = {}

        def fake_run_checks(*args, **kwargs):
            seen["args"] = args
            seen["kwargs"] = kwargs
            rep = vfb.Report()
            rep.add("x", True, {})
            return rep

        monkeypatch.setattr(vfb, "run_checks", fake_run_checks)
        monkeypatch.setattr(sys, "argv", ["verify_fresh_baseline.py"])
        assert vfb.main() == 0
        assert seen["args"] == (False, False, False, False) and seen["kwargs"] == {}
        monkeypatch.setattr(sys, "argv", ["verify_fresh_baseline.py", "--require-otx-industries"])
        assert vfb.main() == 0
        assert seen["args"] == (False, False, False, True)
        monkeypatch.setattr(sys, "argv", ["verify_fresh_baseline.py", "--legacy-graph"])
        with pytest.raises(SystemExit) as exc:
            vfb.main()
        assert exc.value.code == 2


class TestIndicatorCveReportLinks:
    """Check 10a6 (2026-10-18): ``(Indicator)-[:INDICATES]->(CVE)`` says "named in the same OTX report"
    and nothing else: every such link is labelled ``otx_pulse`` and cites the report
    (``alienvault_otx:<pulse id>``). The counts are reported; a graph without such a link is not judged."""

    def test_a_correct_graph_passes_and_the_counts_are_reported(self, vfb, monkeypatch):
        rep = _run(vfb, monkeypatch)
        assert _check(rep, "indicator_cve_links_are_same_report")["ok"] is True
        info = _check(rep, "indicator_cve_report_links")
        assert info["ok"] is None
        assert info["detail"] == dict(_INDICATOR_CVE_ROW, indicates_other_targets=0)

    @pytest.mark.parametrize("defect", ["not_otx_pulse", "without_otx_report"])
    def test_an_unlabelled_or_unsourced_link_fails(self, vfb, monkeypatch, defect):
        def broken(statement, rows):
            if "AS indicator_cve_links" in statement:
                return [dict(_INDICATOR_CVE_ROW, **{defect: 3})]
            return rows

        rep = _run(vfb, monkeypatch, override=broken)
        assert [c["check"] for c in rep.failed] == ["indicator_cve_links_are_same_report"]
        assert _check(rep, "indicator_cve_links_are_same_report")["detail"][defect] == 3

    def test_a_graph_without_such_links_is_not_judged(self, vfb, monkeypatch):
        def none(statement, rows):
            if "AS indicator_cve_links" in statement:
                return [
                    {"indicator_cve_links": 0, "cves": 0, "indicators": 0, "not_otx_pulse": 0, "without_otx_report": 0}
                ]
            return rows

        rep = _run(vfb, monkeypatch, override=none)
        assert _check(rep, "indicator_cve_links_are_same_report")["ok"] is None
        assert rep.failed == []

    def test_the_statements_read_the_link_label_and_the_report(self, vfb, monkeypatch):
        seen = []

        def capture(statement, rows):
            if "INDICATES]->(c:CVE)" in statement or "AS indicates_other_targets" in statement:
                seen.append(" ".join(statement.split()))
            return rows

        _run(vfb, monkeypatch, override=capture)
        links, others = seen
        assert links.startswith("MATCH (i:Indicator)-[r:INDICATES]->(c:CVE)")
        assert "r.match_type = 'otx_pulse'" in links and "x STARTS WITH 'alienvault_otx:'" in links
        assert "apoc.meta.cypher.type(r.source_refs)" in links, "a scalar source_refs is read as a list"
        assert "WHERE NOT x:Malware AND NOT x:CVE" in others

    def test_informational_other_targets_never_fail(self, vfb, monkeypatch):
        def legacy(statement, rows):
            if "AS indicates_other_targets" in statement:
                return [{"indicates_other_targets": 12}]
            return rows

        rep = _run(vfb, monkeypatch, override=legacy)
        assert _check(rep, "indicator_cve_report_links")["detail"]["indicates_other_targets"] == 12
        assert rep.failed == []
