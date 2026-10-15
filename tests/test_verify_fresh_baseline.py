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
from typing import Any, Dict, FrozenSet, List
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
    **{t: _LISTS for t in ("RUNS", "PART_OF_CAMPAIGN", "REFERS_TO")},
    **{
        t: frozenset({"sources", "misp_event_ids"})
        for t in ("HAS_CVSS_v2", "HAS_CVSS_v30", "HAS_CVSS_v31", "HAS_CVSS_v40")
    },
    "SOURCED_FROM": frozenset({"source", "source_refs", "misp_event_ids"}),
}
_SCAN_PROPS = ("sources", "source_refs", "misp_event_ids", "match_type", "source")


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


def _healthy_rows(statement: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Rows a correct fresh baseline would return, keyed on fragments of each check's Cypher."""
    s = statement
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
        kw.get("require_ics", False), kw.get("require_cisa_ics", False), kw.get("require_malwarebazaar", False)
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
        rep = _run(vfb, monkeypatch, require_ics=True, require_cisa_ics=True)
        assert {c["check"] for c in rep.failed} == {"ics_techniques_present", "cisa_ics_source_present"}

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
        for never_tlp in ("Source", "Sector", "Campaign", "CVSSv31", "Host", "Alert", "IP"):
            assert never_tlp not in vfb._TLP_LABELS


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
                if "apoc.meta.cypher.type(r.sources)" in st
                else [{"nodes": 11}]
                if "apoc.meta.cypher.type(n.zone)" in st
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
        # RUNS / PART_OF_CAMPAIGN / REFERS_TO carry no match_type, HAS_CVSS_* no source_refs and
        # SOURCED_FROM no sources: the healthy scan has them all at 0 and the check still passes.
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
        for prop in ("sources", "source_refs", "misp_event_ids", "match_type"):
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

    @pytest.mark.parametrize("source", ["urlhaus", "nvd", "ssl_blacklist"])
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
                return [dict(x, sourced_from=0) if x["source_id"] in ("threatfox", "abuseipdb") else x for x in rows]
            return rows

        c = _check(_run(vfb, monkeypatch, override=override), "default_sources_delivered")
        assert c["ok"] is True and c["detail"]["keyed_sources_without_data"] == ["virustotal", "threatfox", "abuseipdb"]

    def test_classification_follows_the_collectors_keys_and_flags(self, vfb):
        import collector_allowlist
        import source_key_check
        import source_registry

        def canonical(name: str) -> str:
            src = source_registry.get_source(name) or source_registry.get_source(name.split("_enrich")[0])
            assert src is not None, name
            return src.canonical_id

        collectors = {canonical(n) for n in collector_allowlist.COLLECT_SOURCES_CANONICAL}
        keyed = {canonical(s.name) for s in source_key_check.KEYED_SOURCES if s.needs_key}
        flagged = {s for s in collectors - keyed if not source_registry.get_source(s).cli_default_enabled}
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
        code, out = self._main(vfb, monkeypatch, capsys, [], "urlhaus")
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
                return [dict(x, sourced_from=0) if x["source_id"] == "urlhaus" else x for x in rows]
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
        code, out = self._main(vfb, monkeypatch, capsys, ["--json"], "urlhaus")
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
