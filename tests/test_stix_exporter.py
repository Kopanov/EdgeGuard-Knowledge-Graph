"""Unit tests for src/stix_exporter.py.

We mock the Neo4j driver so these run without a live DB. The goal is to
validate the shape of the emitted STIX 2.1 bundles and the deterministic
ID behaviour, not to exercise real Cypher.
"""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock

from stix_exporter import StixExporter, _deterministic_id

# ---------------------------------------------------------------------------
# Fake Neo4j driver
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, rows: List[Dict[str, Any]]):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


class _FakeSession:
    def __init__(self, rows: List[Dict[str, Any]]):
        self._rows = rows
        self.last_cypher: str = ""
        self.last_params: Dict[str, Any] = {}

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def run(self, cypher: str, **params: Any) -> _FakeResult:
        self.last_cypher = cypher
        self.last_params = params
        return _FakeResult(self._rows)


class _FakeDriver:
    def __init__(self, rows: List[Dict[str, Any]]):
        self._session = _FakeSession(rows)
        self.last_session_kwargs: Dict[str, Any] = {}

    def session(self, **kwargs: Any):
        # Mirrors neo4j.Driver.session(**kwargs). The exporter passes
        # default_access_mode="READ" so Neo4j rejects accidental writes —
        # we capture the kwargs here so tests can assert on them.
        self.last_session_kwargs = kwargs
        return self._session


def _mk_client(rows: List[Dict[str, Any]]) -> Any:
    client = MagicMock()
    client.driver = _FakeDriver(rows)
    client.is_connected.return_value = True
    return client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _by_type(bundle: Dict[str, Any], stix_type: str) -> List[Dict[str, Any]]:
    return [o for o in bundle["objects"] if o["type"] == stix_type]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_actor_with_two_techniques_yields_intrusion_set_and_uses_sros():
    rows = [
        {
            "seed": {"name": "APT28", "aliases": ["Fancy Bear"]},
            "malware": [],
            "actor_tech": [
                {"mitre_id": "T1055", "name": "Process Injection"},
                {"mitre_id": "T1059", "name": "Command and Scripting Interpreter"},
            ],
            "mal_tech": [],
            "campaigns": [],
        }
    ]
    exporter = StixExporter(_mk_client(rows))
    bundle = exporter.export_threat_actor("APT28")

    intrusion_sets = _by_type(bundle, "intrusion-set")
    attack_patterns = _by_type(bundle, "attack-pattern")
    relationships = _by_type(bundle, "relationship")

    assert len(intrusion_sets) == 1
    assert intrusion_sets[0]["name"] == "APT28"
    assert len(attack_patterns) == 2
    # Two "uses" SROs from the intrusion-set to each attack-pattern.
    uses = [r for r in relationships if r["relationship_type"] == "uses"]
    assert len(uses) == 2
    assert all(r["source_ref"] == intrusion_sets[0]["id"] for r in uses)


def test_actor_with_attributed_malware_emits_attributed_to_sro():
    rows = [
        {
            "seed": {"name": "APT28"},
            "malware": [{"name": "X-Agent", "malware_types": ["trojan"]}],
            "actor_tech": [],
            "mal_tech": [],
            "campaigns": [],
        }
    ]
    exporter = StixExporter(_mk_client(rows))
    bundle = exporter.export_threat_actor("APT28")

    malware = _by_type(bundle, "malware")
    rels = _by_type(bundle, "relationship")
    assert len(malware) == 1 and malware[0]["name"] == "X-Agent"
    attributed = [r for r in rels if r["relationship_type"] == "attributed-to"]
    assert len(attributed) == 1
    assert attributed[0]["source_ref"] == malware[0]["id"]
    assert attributed[0]["target_ref"].startswith("intrusion-set--")


def test_indicator_indicates_malware_bundle():
    rows = [
        {
            "seed": {
                "value": "1.2.3.4",
                "indicator_type": "ipv4",
                "first_seen": "2024-01-01T00:00:00Z",
            },
            "malware": [{"name": "Emotet", "malware_types": ["trojan"]}],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    exporter = StixExporter(_mk_client(rows))
    bundle = exporter.export_indicator("1.2.3.4")

    assert len(_by_type(bundle, "indicator")) == 1
    assert len(_by_type(bundle, "malware")) == 1
    rels = _by_type(bundle, "relationship")
    indicates = [r for r in rels if r["relationship_type"] == "indicates"]
    assert len(indicates) == 1
    assert indicates[0]["target_ref"].startswith("malware--")


def test_deterministic_ids_stable_across_calls():
    rows = [
        {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    e1 = StixExporter(_mk_client(rows))
    e2 = StixExporter(_mk_client(rows))
    b1 = e1.export_indicator("1.2.3.4")
    b2 = e2.export_indicator("1.2.3.4")
    # Bundle IDs differ (random), but object IDs must be identical.
    ids1 = sorted(o["id"] for o in b1["objects"])
    ids2 = sorted(o["id"] for o in b2["objects"])
    assert ids1 == ids2
    assert ids1  # not empty


def test_deterministic_id_helper_uses_uuid5():
    a = _deterministic_id("indicator", "ipv4|1.2.3.4")
    b = _deterministic_id("indicator", "ipv4|1.2.3.4")
    c = _deterministic_id("indicator", "ipv4|9.9.9.9")
    assert a == b
    assert a != c
    assert a.startswith("indicator--")


def test_technique_kill_chain_phases_emitted_as_property_not_sro():
    rows = [
        {
            "seed": {
                "mitre_id": "T1055",
                "name": "Process Injection",
                "tactic_phases": ["defense-evasion", "privilege-escalation"],
            },
            "actors": [],
            "malware": [],
            "tools": [],
            "indicators": [],
        }
    ]
    exporter = StixExporter(_mk_client(rows))
    bundle = exporter.export_technique("T1055")

    ap = _by_type(bundle, "attack-pattern")
    assert len(ap) == 1
    kcp = ap[0].get("kill_chain_phases") or []
    assert {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"} in kcp
    assert {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"} in kcp
    # No Tactic SDO and no in_tactic/IN_TACTIC SRO
    assert _by_type(bundle, "x-mitre-tactic") == []
    rels = _by_type(bundle, "relationship")
    assert not any(r["relationship_type"] in ("in-tactic", "IN_TACTIC") for r in rels)
    # External reference to MITRE ATT&CK
    assert ap[0]["external_references"][0]["source_name"] == "mitre-attack"
    assert ap[0]["external_references"][0]["external_id"] == "T1055"


def test_legacy_uses_rel_type_is_queried_for_backward_compat():
    """The Cypher for actor/technique export must still match the legacy
    ``USES`` rel type alongside the new EMPLOYS_/IMPLEMENTS_TECHNIQUE ones.
    We assert this by inspecting the query string the exporter ran.
    """
    rows = [
        {
            "seed": {"name": "APT29"},
            "malware": [],
            "actor_tech": [],
            "mal_tech": [],
            "campaigns": [],
        }
    ]
    client = _mk_client(rows)
    exporter = StixExporter(client)
    exporter.export_threat_actor("APT29")
    q = client.driver._session.last_cypher
    assert "EMPLOYS_TECHNIQUE|USES" in q
    assert "IMPLEMENTS_TECHNIQUE|USES" in q

    # And the technique-centric export also checks the legacy variant.
    rows2 = [
        {
            "seed": {"mitre_id": "T1059", "name": "CLI", "tactic_phases": []},
            "actors": [],
            "malware": [],
            "tools": [],
            "indicators": [],
        }
    ]
    client2 = _mk_client(rows2)
    StixExporter(client2).export_technique("T1059")
    q2 = client2.driver._session.last_cypher
    assert "EMPLOYS_TECHNIQUE|USES" in q2
    assert "IMPLEMENTS_TECHNIQUE|USES" in q2
    assert "USES_TECHNIQUE|USES" in q2


def test_edgeguard_managed_filter_present_in_all_queries():
    rows = [
        {
            "seed": {"value": "evil.com", "indicator_type": "domain"},
            "malware": [],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    client = _mk_client(rows)
    StixExporter(client).export_indicator("evil.com")
    q = client.driver._session.last_cypher
    # Bugbot regression: the original filter used
    # `coalesce(x.edgeguard_managed, true) = true`, which defaulted missing
    # properties to true and let ResilMesh-owned nodes leak through. Enforce
    # strict equality — `x.edgeguard_managed = true` — so null fails the
    # check and only EdgeGuard-owned nodes can be exported.
    assert "edgeguard_managed = true" in q
    assert "coalesce(" not in q or "coalesce(i.edgeguard_managed" not in q


def test_session_opened_with_read_access_mode():
    """Exporter must open Neo4j sessions with default_access_mode='READ'
    so the driver rejects any accidental write — matches the defense-
    in-depth pattern in query_api.py graph-explore and admin-query
    endpoints. Regression test for a bugbot finding on PR #25."""
    rows = [
        {
            "seed": {"value": "evil.com", "indicator_type": "domain"},
            "malware": [],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    client = _mk_client(rows)
    StixExporter(client).export_indicator("evil.com")
    assert client.driver.last_session_kwargs.get("default_access_mode") == "READ"


def test_cve_export_uses_affects_not_targets_for_sectors():
    """Vulnerability/CVE→Sector edges are written as AFFECTS by
    build_relationships.py, not TARGETS (TARGETS is reserved for
    Indicator→Sector). Regression test for a bugbot finding on PR #25
    where the Cypher silently returned zero sectors for every CVE."""
    rows = [
        {
            "seed": {"cve_id": "CVE-2021-44228"},
            "indicators": [],
            "sectors": [],
        }
    ]
    client = _mk_client(rows)
    StixExporter(client).export_cve("CVE-2021-44228")
    q = client.driver._session.last_cypher
    assert "[:AFFECTS]->(s:Sector)" in q
    assert "[:TARGETS]->(s:Sector)" not in q


def test_cve_export_bundle_contains_vulnerability_and_indicator_indicates_rel():
    rows = [
        {
            "seed": {"cve_id": "CVE-2021-44228", "name": "Log4Shell"},
            "indicators": [
                {"value": "evil.com", "indicator_type": "domain"},
            ],
            "sectors": [],
        }
    ]
    exporter = StixExporter(_mk_client(rows))
    bundle = exporter.export_cve("CVE-2021-44228")
    vulns = _by_type(bundle, "vulnerability")
    assert len(vulns) == 1
    assert vulns[0]["external_references"][0]["source_name"] == "cve"
    assert vulns[0]["external_references"][0]["external_id"] == "CVE-2021-44228"
    rels = _by_type(bundle, "relationship")
    assert any(
        r["relationship_type"] == "indicates"
        and r["target_ref"] == vulns[0]["id"]
        for r in rels
    )


def test_empty_bundle_when_seed_not_found():
    exporter = StixExporter(_mk_client([]))
    bundle = exporter.export_indicator("nothing-here")
    assert bundle["type"] == "bundle"
    assert bundle["objects"] == []
