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
import os
import sys
from typing import Any, Dict, List

import pytest

_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "scripts", "verify_fresh_baseline.py")


@pytest.fixture(scope="module")
def vfb():
    spec = importlib.util.spec_from_file_location("verify_fresh_baseline", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules.setdefault("verify_fresh_baseline", mod)
    spec.loader.exec_module(mod)
    return mod


def _healthy_rows(statement: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Rows a correct fresh baseline would return, keyed on fragments of each check's Cypher."""
    s = statement
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
    if "n.edgeguard_managed IS NULL UNWIND labels(n)" in s:
        return [{"label": "Alert", "c": 3}, {"label": "Host", "c": 2}]
    if "r.edgeguard_managed IS NULL RETURN type(r)" in s:
        return [{"type": "INVOLVES", "c": 3}]
    if "coalesce(t.attack_domain, 'enterprise') <> coalesce(tc.attack_domain, 'enterprise')" in s:
        return [{"c": 0}]
    if "Technique {attack_domain: 'ics'}" in s:
        return [{"c": 0}]
    if "source_id: 'cisa_ics'" in s:
        return [{"present": False, "edges": 0}]
    if "db.relationshipTypes" in s:
        return [{"t": t} for t in ("SOURCED_FROM", "INDICATES", "INVOLVES", "ON")]
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
    raise AssertionError(f"unexpected statement in test dispatcher: {statement[:120]}")


def _run(vfb, monkeypatch, override=None, **kw):
    def fake_post(statement, params=None, timeout=180):
        rows = _healthy_rows(statement, params or {})
        return override(statement, rows) if override else rows

    monkeypatch.setattr(vfb, "_post", fake_post)
    return vfb.run_checks(kw.get("require_ics", False), kw.get("require_cisa_ics", False))


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


class TestNoFalsePositives:
    def test_alert_subgraph_without_marker_does_not_fail_ownership_checks(self, vfb, monkeypatch):
        """Alert / Host nodes and INVOLVES edges are written by the alert processor without the
        marker; they are not part of the baseline contract and must only be reported."""
        rep = _run(vfb, monkeypatch)
        assert _check(rep, "ownership_marker_on_nodes")["ok"] is True
        assert _check(rep, "ownership_marker_on_edges")["ok"] is True
        assert "INVOLVES" not in vfb.EDGEGUARD_REL_TYPES

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
