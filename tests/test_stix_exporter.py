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


def test_actor_campaign_query_uses_runs_direction():
    """Regression test for bugbot round-4 finding: the export_threat_actor
    Cypher was originally ``(c:Campaign)-[:ATTRIBUTED_TO]->(a)`` but the
    actual graph edge is ``(a:ThreatActor)-[:RUNS]->(c:Campaign)`` —
    see enrichment_jobs.build_campaign_nodes(). The wrong pattern
    matched zero campaigns for every actor, silently omitting them
    from STIX bundles."""
    rows = [
        {
            "seed": {"name": "APT28"},
            "malware": [],
            "actor_tech": [],
            "mal_tech": [],
            "campaigns": [{"name": "OperationPawnStorm"}],
        }
    ]
    client = _mk_client(rows)
    StixExporter(client).export_threat_actor("APT28")
    q = client.driver._session.last_cypher
    # The query must match (a:ThreatActor)-[:RUNS]->(c:Campaign), not
    # the reverse. Match on the full pattern so a future refactor that
    # accidentally flips direction fails loudly here.
    assert "(a)-[:RUNS]->(c:Campaign)" in q
    assert "(c:Campaign)-[:ATTRIBUTED_TO]->(a)" not in q


def test_export_technique_uses_with_aggregation_to_avoid_cartesian():
    """Regression test for bugbot round-4 finding: the export_technique
    Cypher chained four OPTIONAL MATCH clauses without intermediate
    aggregation, producing a Cartesian product for well-connected
    techniques. The fix adds ``WITH t, collect(DISTINCT ...) AS ...``
    between each clause. Assert the WITH aggregation is in the emitted
    Cypher so a future regression is caught."""
    rows = [
        {
            "seed": {"mitre_id": "T1059", "name": "Command and Scripting Interpreter"},
            "actors": [],
            "malware": [],
            "tools": [],
            "indicators": [],
        }
    ]
    client = _mk_client(rows)
    StixExporter(client).export_technique("T1059")
    q = client.driver._session.last_cypher
    # Must see the aggregation step between OPTIONAL MATCH clauses.
    assert "collect(DISTINCT a) AS actors" in q
    assert "collect(DISTINCT m) AS malware" in q
    assert "collect(DISTINCT tool) AS tools" in q
    # And the first WITH must be between the seed match and the first
    # OPTIONAL MATCH so actors don't multiply the seed row.
    assert "WITH t\n" in q or "WITH t " in q


def test_export_indicator_uses_with_aggregation_to_avoid_cartesian():
    """Regression test for bugbot round-5 finding: the export_indicator
    Cypher chained four OPTIONAL MATCH clauses without intermediate
    aggregation, producing an O(malware × vulns × techniques × sectors)
    Cartesian product for well-connected indicators. Same pattern as the
    round-2/round-4 fixes to export_threat_actor and export_technique."""
    rows = [
        {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    client = _mk_client(rows)
    StixExporter(client).export_indicator("1.2.3.4")
    q = client.driver._session.last_cypher
    # Each collection must be folded into a WITH before the next OPTIONAL MATCH.
    assert "collect(DISTINCT m) AS malware" in q
    assert "collect(DISTINCT v) AS vulns" in q
    assert "collect(DISTINCT t) AS techniques" in q
    # First WITH must be between the seed match and the first OPTIONAL MATCH.
    assert "WITH i, collect(DISTINCT m) AS malware" in q


def test_export_cve_uses_with_aggregation_to_avoid_cartesian():
    """Regression test for bugbot round-6 finding: export_cve chained
    two OPTIONAL MATCH clauses (indicators, sectors) without
    intermediate WITH aggregation. A well-linked CVE (Log4Shell has
    ~100 exploiting indicators × ~5 sectors = ~500 pre-DISTINCT rows)
    would materialise the product before the outer collect collapses
    it. Same pattern as the round-2/round-4/round-5 fixes to the
    other exporters."""
    rows = [
        {
            "seed": {"cve_id": "CVE-2021-44228", "name": "Log4Shell"},
            "indicators": [],
            "sectors": [],
        }
    ]
    client = _mk_client(rows)
    StixExporter(client).export_cve("CVE-2021-44228")
    q = client.driver._session.last_cypher
    # Aggregation step between the two OPTIONAL MATCHes.
    assert "WITH v, collect(DISTINCT i) AS indicators" in q
    # Sectors still collected at RETURN time.
    assert "collect(DISTINCT s) AS sectors" in q


def test_stix_exporter_passes_query_timeout():
    """Regression test for bugbot round-5 finding: _run was calling
    session.run without a timeout, so a pathological export query could
    hang the request handler indefinitely. Every other session.run call
    in query_api.py and neo4j_client.py passes a timeout — the exporter
    now matches that pattern."""
    rows = [
        {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    client = _mk_client(rows)
    StixExporter(client).export_indicator("1.2.3.4")
    # FakeSession.run captures every keyword arg into last_params. In
    # production, session.run(cypher, **query_params, timeout=300) puts
    # `timeout` into that same **kwargs, so asserting on last_params is
    # how we verify the exporter sets it.
    last_params = client.driver._session.last_params
    assert "timeout" in last_params, "session.run must be called with an explicit timeout"
    assert isinstance(last_params["timeout"], (int, float))
    assert last_params["timeout"] > 0


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
    assert any(r["relationship_type"] == "indicates" and r["target_ref"] == vulns[0]["id"] for r in rels)


def test_empty_bundle_when_seed_not_found():
    exporter = StixExporter(_mk_client([]))
    bundle = exporter.export_indicator("nothing-here")
    assert bundle["type"] == "bundle"
    assert bundle["objects"] == []


# ---------------------------------------------------------------------------
# ResilMesh-quickstart features: zones, depth, provenance
# ---------------------------------------------------------------------------


def test_zone_tags_attached_as_custom_property_on_sdo():
    """Neo4j nodes with a `zone` list should emit `x_edgeguard_zones`
    on the SDO so ResilMesh can filter bundles by sector without
    traversing the graph. Resolves proposal §7 open question 4."""
    rows = [
        {
            "seed": {
                "value": "1.2.3.4",
                "indicator_type": "ipv4",
                "zone": ["healthcare", "global"],
            },
            "malware": [
                {"name": "Emotet", "malware_types": ["trojan"], "zone": ["finance"]},
            ],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    exporter = StixExporter(_mk_client(rows))
    bundle = exporter.export_indicator("1.2.3.4")
    ind = _by_type(bundle, "indicator")[0]
    mal = _by_type(bundle, "malware")[0]
    assert ind["x_edgeguard_zones"] == ["healthcare", "global"]
    assert mal["x_edgeguard_zones"] == ["finance"]


def test_sdo_has_no_zone_property_when_node_has_no_zones():
    """Don't add an empty `x_edgeguard_zones` on every SDO — omit the
    key entirely so unaffected bundles stay lean."""
    rows = [
        {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    bundle = StixExporter(_mk_client(rows)).export_indicator("1.2.3.4")
    ind = _by_type(bundle, "indicator")[0]
    assert "x_edgeguard_zones" not in ind


def test_bundle_carries_x_edgeguard_source_provenance():
    """Every bundle — including empty ones — must carry bundle-level
    provenance so ResilMesh can tell which EdgeGuard build produced it."""
    rows = [
        {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    bundle = StixExporter(_mk_client(rows)).export_indicator("1.2.3.4")
    assert "x_edgeguard_source" in bundle
    src = bundle["x_edgeguard_source"]
    assert src["producer"] == "EdgeGuard Knowledge Graph"
    assert src["exporter"] == "stix_exporter"
    assert src["spec_version"] == "2.1"
    assert "generated_at" in src
    # generated_at is ISO 8601 Z-suffixed UTC
    assert src["generated_at"].endswith("Z")
    assert "T" in src["generated_at"]


def test_empty_bundle_also_carries_provenance():
    bundle = StixExporter(_mk_client([])).export_indicator("nothing-here")
    assert bundle["objects"] == []
    assert "x_edgeguard_source" in bundle


def test_depth_1_indicator_skips_non_primary_relations():
    """depth=1 returns only the seed + primary relation type
    (INDICATES→Malware for indicators). CVE/technique/sector groups
    are omitted — the bundle is a minimal smoke-test payload."""
    rows = [
        {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [{"name": "Emotet", "malware_types": ["trojan"]}],
            "vulns": [{"cve_id": "CVE-2021-44228", "name": "Log4Shell"}],
            "techniques": [{"mitre_id": "T1059", "name": "Cmd Scripting"}],
            "sectors": [{"name": "finance"}],
        }
    ]
    exporter = StixExporter(_mk_client(rows))
    bundle_1 = exporter.export_indicator("1.2.3.4", depth=1)
    bundle_2 = exporter.export_indicator("1.2.3.4", depth=2)
    # Minimal bundle: seed + malware + the INDICATES SRO. Nothing else.
    types_1 = {o["type"] for o in bundle_1["objects"]}
    assert "indicator" in types_1
    assert "malware" in types_1
    assert "vulnerability" not in types_1
    assert "attack-pattern" not in types_1
    assert "identity" not in types_1  # sectors map to identity SDOs
    # Full bundle has all of them (regression guard — default behavior
    # is unchanged by the depth knob).
    types_2 = {o["type"] for o in bundle_2["objects"]}
    assert {"indicator", "malware", "vulnerability", "attack-pattern", "identity"} <= types_2


def test_depth_1_actor_skips_techniques_and_campaigns():
    rows = [
        {
            "seed": {"name": "APT28"},
            "malware": [{"name": "X-Agent", "malware_types": ["trojan"]}],
            "actor_tech": [{"mitre_id": "T1055", "name": "Process Injection"}],
            "mal_tech": [],
            "campaigns": [{"name": "PawnStorm"}],
        }
    ]
    bundle = StixExporter(_mk_client(rows)).export_threat_actor("APT28", depth=1)
    types = {o["type"] for o in bundle["objects"]}
    assert "intrusion-set" in types
    assert "malware" in types  # primary
    assert "attack-pattern" not in types  # actor techniques omitted
    assert "campaign" not in types  # campaigns omitted


def test_depth_1_technique_skips_malware_tools_indicators():
    rows = [
        {
            "seed": {"mitre_id": "T1059", "name": "Cmd Scripting"},
            "actors": [{"name": "APT28"}],
            "malware": [{"name": "Emotet", "malware_types": ["trojan"]}],
            "tools": [{"name": "Cobalt Strike"}],
            "indicators": [{"value": "1.2.3.4", "indicator_type": "ipv4"}],
        }
    ]
    bundle = StixExporter(_mk_client(rows)).export_technique("T1059", depth=1)
    types = {o["type"] for o in bundle["objects"]}
    assert "attack-pattern" in types
    assert "intrusion-set" in types  # primary
    assert "malware" not in types
    assert "tool" not in types
    assert "indicator" not in types


def test_depth_1_cve_skips_sectors():
    rows = [
        {
            "seed": {"cve_id": "CVE-2021-44228", "name": "Log4Shell"},
            "indicators": [{"value": "evil.com", "indicator_type": "domain"}],
            "sectors": [{"name": "finance"}],
        }
    ]
    bundle = StixExporter(_mk_client(rows)).export_cve("CVE-2021-44228", depth=1)
    types = {o["type"] for o in bundle["objects"]}
    assert "vulnerability" in types
    assert "indicator" in types  # primary
    assert "identity" not in types  # sector identity omitted
    rels = _by_type(bundle, "relationship")
    # No targets SRO (sector-related) in a depth=1 CVE bundle.
    assert not any(r["relationship_type"] == "targets" for r in rels)


def test_depth_default_preserves_legacy_behavior():
    """Calling export_indicator() with no depth kwarg must match
    depth=2 exactly — the knob is opt-in and must not break callers
    that were written against the pre-depth API."""
    rows = [
        {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [{"name": "Emotet", "malware_types": ["trojan"]}],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    exporter = StixExporter(_mk_client(rows))
    default = exporter.export_indicator("1.2.3.4")
    explicit = exporter.export_indicator("1.2.3.4", depth=2)
    # Object IDs and types must match. Bundle IDs differ (random).
    ids_default = sorted(o["id"] for o in default["objects"])
    ids_explicit = sorted(o["id"] for o in explicit["objects"])
    assert ids_default == ids_explicit
