"""Unit tests for src/stix_exporter.py.

We mock the Neo4j driver so these run without a live DB. The goal is to
validate the shape of the emitted STIX 2.1 bundles and the deterministic
ID behaviour, not to exercise real Cypher.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest
import stix2

# ``query_api`` reads these at import time; the route tests below import it
# lazily, so the defaults are set here (same values as tests/test_query_api.py).
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "test-password")
os.environ.setdefault("EDGEGUARD_ENV", "dev")

import stix_exporter
from stix_exporter import (
    EDGEGUARD_EXTENSION_ID,
    EDGEGUARD_IDENTITY_ID,
    StixExporter,
    _build_pattern,
    _deterministic_id,
)

# ---------------------------------------------------------------------------
# Fake Neo4j driver
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, rows: List[Dict[str, Any]]):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


_AGGREGATE_LABEL_RE = re.compile(r"MATCH \(n:(\w+)\)")


def _aggregate_label(cypher: str) -> str:
    """Node label targeted by a batched ``SOURCED_FROM`` aggregate statement.

    The CVE / Vulnerability twins are matched by either label
    (``(n:CVE OR n:Vulnerability)``); that form is reported as
    ``Vulnerability``, the label the exporter prefetches under.
    """
    if "(n:CVE OR n:Vulnerability)" in cypher:
        return "Vulnerability"
    match = _AGGREGATE_LABEL_RE.search(cypher)
    return match.group(1) if match else ""


class _FakeSession:
    def __init__(
        self,
        rows: List[Dict[str, Any]],
        aggregate_rows_by_label: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ):
        self._rows = rows
        # Rows returned for the batched ``SOURCED_FROM`` aggregate query of
        # a given label (``_prefetch_source_aggregates``). Labels without an
        # entry return no rows. When ``None`` every query returns ``rows``.
        self._aggregate_rows_by_label = aggregate_rows_by_label
        self.last_cypher: str = ""
        self.last_params: Dict[str, Any] = {}
        # The exporter runs the export query first and then one batched
        # source-aggregate query per node label. ``cypher_history`` keeps
        # the ordered list of statements and ``call_history`` the
        # (statement, parameters) pairs; ``main_cypher`` is the FIRST
        # statement (the export query).
        self.cypher_history: List[str] = []
        self.call_history: List[Tuple[str, Dict[str, Any]]] = []

    @property
    def main_cypher(self) -> str:
        """The first Cypher executed in this session — the export
        query (NOT a follow-up source-truthful aggregate)."""
        return self.cypher_history[0] if self.cypher_history else ""

    @property
    def main_params(self) -> Dict[str, Any]:
        return self.call_history[0][1] if self.call_history else {}

    @property
    def aggregate_calls(self) -> List[Tuple[str, Dict[str, Any]]]:
        """The batched ``SOURCED_FROM`` aggregate statements, in order."""
        return [(c, p) for c, p in self.call_history if "SOURCED_FROM" in c]

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def run(self, cypher: str, **params: Any) -> _FakeResult:
        self.last_cypher = cypher
        self.last_params = params
        self.cypher_history.append(cypher)
        self.call_history.append((cypher, params))
        if self._aggregate_rows_by_label is not None and "SOURCED_FROM" in cypher:
            return _FakeResult(self._aggregate_rows_by_label.get(_aggregate_label(cypher), []))
        return _FakeResult(self._rows)


class _FakeDriver:
    def __init__(
        self,
        rows: List[Dict[str, Any]],
        aggregate_rows_by_label: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ):
        self._session = _FakeSession(rows, aggregate_rows_by_label)
        self.last_session_kwargs: Dict[str, Any] = {}

    def session(self, **kwargs: Any):
        # Mirrors neo4j.Driver.session(**kwargs). The exporter passes
        # default_access_mode="READ" so Neo4j rejects accidental writes —
        # we capture the kwargs here so tests can assert on them.
        self.last_session_kwargs = kwargs
        return self._session


def _mk_client(
    rows: List[Dict[str, Any]],
    aggregate_rows_by_label: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> Any:
    client = MagicMock()
    client.driver = _FakeDriver(rows, aggregate_rows_by_label)
    client.is_connected.return_value = True
    return client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Object types every bundle carries regardless of the seed: the producer
# identity, the extension definition and the referenced TLP markings.
_PROVENANCE_TYPES = {"extension-definition", "marking-definition"}


def _by_type(bundle: Dict[str, Any], stix_type: str) -> List[Dict[str, Any]]:
    return [o for o in bundle["objects"] if o["type"] == stix_type]


def _exported(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Objects built from graph nodes/edges — without the provenance objects."""
    return [o for o in bundle["objects"] if o["type"] not in _PROVENANCE_TYPES and o["id"] != EDGEGUARD_IDENTITY_ID]


def _sector_identities(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [o for o in _by_type(bundle, "identity") if o["id"] != EDGEGUARD_IDENTITY_ID]


def _producer_identity(bundle: Dict[str, Any]) -> Dict[str, Any]:
    return next(o for o in bundle["objects"] if o["id"] == EDGEGUARD_IDENTITY_ID)


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
    q = client.driver._session.main_cypher
    # The query must match (a:ThreatActor)-[:RUNS]->(c:Campaign), not
    # the reverse. Match on the full pattern so a future refactor that
    # accidentally flips direction fails loudly here.
    assert "(a)-[r4:RUNS]->(c:Campaign)" in q
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
    q = client.driver._session.main_cypher
    # Must see the aggregation step between OPTIONAL MATCH clauses.
    # 2026-10: each collection carries its relationship's properties (SRO provenance)
    assert "collect({n: a, r: properties(r1)}) AS actors" in q
    assert "collect({n: m, r: properties(r2)}) AS malware" in q
    assert "collect({n: tool, r: properties(r3)}) AS tools" in q
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
    q = client.driver._session.main_cypher
    # Each collection must be folded into a WITH before the next OPTIONAL MATCH.
    assert "collect({n: m, r: properties(r1)}) AS malware" in q
    assert "collect(vr) AS vulns" in q
    assert "collect({n: t, r: properties(r3)}) AS techniques" in q
    # First WITH must be between the seed match and the first OPTIONAL MATCH.
    assert "WITH i, collect({n: m, r: properties(r1)}) AS malware" in q


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
    q = client.driver._session.main_cypher
    # Aggregation step between the two OPTIONAL MATCHes.
    assert "WITH seed, twins, collect({n: i, r: r1s}) AS indicators" in q
    # Sectors still collected at RETURN time.
    assert "collect({n: s, r: r3s}) AS sectors" in q


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


def test_actor_with_attributed_malware_emits_intrusion_set_uses_malware_sro():
    """The graph edge is (Malware)-[:ATTRIBUTED_TO]->(ThreatActor). STIX 2.1
    defines ``attributed-to`` only for campaign / intrusion-set sources; the
    pair is modelled as ``intrusion-set uses malware`` (the MITRE ATT&CK
    form these edges derive from), so the SRO is reversed on export."""
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
    assert not any(r["relationship_type"] == "attributed-to" for r in rels)
    uses = [r for r in rels if r["relationship_type"] == "uses"]
    assert len(uses) == 1
    assert uses[0]["source_ref"].startswith("intrusion-set--")
    assert uses[0]["target_ref"] == malware[0]["id"]


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


def test_specialised_technique_rel_types_only_no_legacy_uses():
    """PR #33 round 12 dropped the rollout-window ``|USES`` fallback. The
    Cypher for actor/technique export must MATCH only the post-PR-#24
    specialised rel types (EMPLOYS_TECHNIQUE / IMPLEMENTS_TECHNIQUE /
    USES_TECHNIQUE) — no legacy ``USES`` alternation. Pre-release fresh
    start has no legacy USES edges in any database."""
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
    q = client.driver._session.main_cypher
    assert "EMPLOYS_TECHNIQUE" in q
    assert "IMPLEMENTS_TECHNIQUE" in q
    # Legacy fallback must NOT be back.
    assert "EMPLOYS_TECHNIQUE|USES" not in q, "round-12 dropped the |USES fallback"
    assert "IMPLEMENTS_TECHNIQUE|USES" not in q, "round-12 dropped the |USES fallback"

    # Same check on the technique-centric export.
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
    q2 = client2.driver._session.main_cypher
    assert "EMPLOYS_TECHNIQUE" in q2
    assert "IMPLEMENTS_TECHNIQUE" in q2
    assert "USES_TECHNIQUE" in q2
    assert "EMPLOYS_TECHNIQUE|USES" not in q2
    assert "IMPLEMENTS_TECHNIQUE|USES" not in q2
    assert "USES_TECHNIQUE|USES" not in q2


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
    q = client.driver._session.main_cypher
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
    q = client.driver._session.main_cypher
    assert "[r3:AFFECTS]->(s:Sector)" in q
    assert ":TARGETS]->(s:Sector)" not in q


def test_cve_export_bundle_contains_vulnerability_and_indicator_related_to_rel():
    """STIX 2.1 defines no indicator → vulnerability relationship (``indicates``
    targets attack-pattern, campaign, infrastructure, intrusion-set, malware,
    threat-actor and tool only), so EXPLOITS is exported as ``related-to``."""
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
    to_vuln = [r for r in rels if r["target_ref"] == vulns[0]["id"]]
    assert len(to_vuln) == 1
    assert to_vuln[0]["relationship_type"] == "related-to"
    assert to_vuln[0]["source_ref"].startswith("indicator--")


def test_empty_bundle_when_seed_not_found():
    exporter = StixExporter(_mk_client([]))
    bundle = exporter.export_indicator("nothing-here")
    assert bundle["type"] == "bundle"
    # No graph-derived objects; only the provenance objects remain.
    assert _exported(bundle) == []
    assert {o["type"] for o in bundle["objects"]} == {"identity", "extension-definition", "marking-definition"}


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


def test_bundle_carries_producer_identity_provenance(monkeypatch):
    """Every bundle — including empty ones — must carry provenance so
    ResilMesh can tell which EdgeGuard build produced it. STIX 2.1 permits
    no custom properties on the Bundle itself, so the provenance lives on
    the EdgeGuard producer ``identity`` as top-level extension properties."""
    monkeypatch.setattr(stix_exporter, "_GIT_SHA", "d5dc41f")
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
    assert set(bundle) == {"type", "id", "objects"}, "a STIX 2.1 Bundle carries only type, id and objects"
    ident = _producer_identity(bundle)
    assert ident["type"] == "identity"
    assert ident["name"] == "EdgeGuard Knowledge Graph"
    assert ident["identity_class"] == "system"
    assert ident["x_edgeguard_exporter"] == "stix_exporter"
    assert ident["x_edgeguard_git_sha"] == "d5dc41f"
    # generated_at is ISO 8601 Z-suffixed UTC
    assert ident["x_edgeguard_generated_at"].endswith("Z")
    assert "T" in ident["x_edgeguard_generated_at"]
    assert ident["extensions"] == {EDGEGUARD_EXTENSION_ID: {"extension_type": "toplevel-property-extension"}}
    # Every exported object names the identity as its creator.
    for o in _exported(bundle):
        assert o["created_by_ref"] == EDGEGUARD_IDENTITY_ID, o["id"]


def test_empty_bundle_also_carries_provenance():
    bundle = StixExporter(_mk_client([])).export_indicator("nothing-here")
    assert _exported(bundle) == []
    ident = _producer_identity(bundle)
    assert ident["x_edgeguard_exporter"] == "stix_exporter"
    assert any(o["type"] == "extension-definition" for o in bundle["objects"])


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
    types_1 = {o["type"] for o in _exported(bundle_1)}
    assert "indicator" in types_1
    assert "malware" in types_1
    assert "vulnerability" not in types_1
    assert "attack-pattern" not in types_1
    assert _sector_identities(bundle_1) == []  # sectors map to identity SDOs
    # Full bundle has all of them (regression guard — default behavior
    # is unchanged by the depth knob).
    types_2 = {o["type"] for o in _exported(bundle_2)}
    assert {"indicator", "malware", "vulnerability", "attack-pattern"} <= types_2
    assert len(_sector_identities(bundle_2)) == 1


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
    types = {o["type"] for o in _exported(bundle)}
    assert "vulnerability" in types
    assert "indicator" in types  # primary
    assert _sector_identities(bundle) == []  # sector identity omitted
    rels = _by_type(bundle, "relationship")
    # No sector-related SRO in a depth=1 CVE bundle.
    assert not any(r["target_ref"].startswith("identity--") for r in rels)


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


# ---------------------------------------------------------------------------
# Export hardening (2026-10): bounded exports, batched aggregates
# ---------------------------------------------------------------------------

_INDICATOR_ROW = {
    "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
    "malware": [],
    "vulns": [],
    "techniques": [],
    "sectors": [],
}
_ACTOR_ROW = {"seed": {"name": "apt28"}, "malware": [], "actor_tech": [], "mal_tech": [], "campaigns": []}
_TECHNIQUE_ROW = {
    "seed": {"mitre_id": "T1059", "name": "CLI"},
    "actors": [],
    "malware": [],
    "tools": [],
    "indicators": [],
}
_CVE_ROW = {"seed": {"cve_id": "CVE-2021-44228"}, "indicators": [], "sectors": []}

_EXPORTS = [
    # 2026-10: + campaign membership (indicator); + USES_MALWARE / USES_TOOL / EXPLOITS /
    # TARGETS (actor); + SUBTECHNIQUE_OF parent and children (technique); + actors and
    # malware exploiting the CVE (cve).
    ("export_indicator", "1.2.3.4", _INDICATOR_ROW, 5),
    ("export_threat_actor", "APT28", _ACTOR_ROW, 8),
    ("export_technique", "T1059", _TECHNIQUE_ROW, 6),
    ("export_cve", "CVE-2021-44228", _CVE_ROW, 3),
]


@pytest.mark.parametrize("method, identifier, row, collections", _EXPORTS)
def test_every_collection_is_ordered_and_limited_by_parameter(method, identifier, row, collections):
    """Each related-node collection must be bounded by a parameterised
    ``LIMIT $limit`` that is preceded by an ``ORDER BY`` on the same stage
    (deterministic truncation). The parameter value is the clamped
    ``limit`` argument."""
    client = _mk_client([row])
    getattr(StixExporter(client), method)(identifier, limit=7)
    q = client.driver._session.main_cypher
    params = client.driver._session.main_params
    assert params["limit"] == 7
    assert "LIMIT $limit" in q
    limited_stages = [line for line in q.splitlines() if "LIMIT $limit" in line]
    assert len(limited_stages) == collections, limited_stages
    for line in limited_stages:
        assert "ORDER BY" in line, f"LIMIT without ORDER BY is non-deterministic: {line.strip()}"
    # No unbounded collect() of related nodes remains: every collect() is
    # preceded by a limited stage, so the counts agree.
    # Collections, not the CVE-twin folds (``head(collect(...))`` / ``collect(v) AS twins``) nor the
    # per-neighbour relationship folds (``collect(properties(r))``, CVE twins).
    folds = q.count("head(collect(") + q.count("collect(v) AS twins") + q.count("collect(properties(")
    assert q.count("collect(") - folds == collections


@pytest.mark.parametrize("method, identifier, row, _collections", _EXPORTS)
def test_limit_default_and_clamping(method, identifier, row, _collections):
    """Omitted ``limit`` → ``_DEFAULT_LIMIT``; values above ``_MAX_LIMIT`` are
    clamped; zero / negative values become 1; non-integers fall back to the
    default."""
    for given, expected in (
        (None, stix_exporter._DEFAULT_LIMIT),
        (10_000, stix_exporter._MAX_LIMIT),
        (0, 1),
        (-5, 1),
        ("abc", stix_exporter._DEFAULT_LIMIT),
    ):
        client = _mk_client([row])
        exporter = StixExporter(client)
        if given is None:
            getattr(exporter, method)(identifier)
        else:
            getattr(exporter, method)(identifier, limit=given)
        assert client.driver._session.main_params["limit"] == expected, (given, expected)


def test_seed_match_is_reduced_to_one_deterministic_row():
    """The per-collection limits are only well defined for a single seed
    row, so the seed stage carries its own ``ORDER BY ... LIMIT 1`` where
    the key is not unique (indicator value across types, actor alias
    hits). The CVE twins are folded into one row instead (properties from
    the CVE-preferred head, relationships walked from every twin).
    Technique.mitre_id is unique and needs none."""
    cases = {
        "export_indicator": ("1.2.3.4", _INDICATOR_ROW, "WITH i ORDER BY i.indicator_type LIMIT 1"),
        "export_threat_actor": ("APT28", _ACTOR_ROW, "ORDER BY _match_rank, a.name\n            LIMIT 1"),
        "export_cve": (
            "CVE-2021-44228",
            _CVE_ROW,
            "WITH v ORDER BY (CASE WHEN v:CVE THEN 0 ELSE 1 END)\n"
            "            WITH head(collect(v)) AS seed, collect(v) AS twins",
        ),
    }
    for method, (identifier, row, fragment) in cases.items():
        client = _mk_client([row])
        getattr(StixExporter(client), method)(identifier)
        assert fragment in client.driver._session.main_cypher, method


def test_source_aggregates_use_exactly_one_batched_query_per_label():
    """The per-source MIN/MAX timestamps are fetched with ONE ``UNWIND``
    query per node label and bundle — never one query per node. Sector
    nodes carry no per-source claims and are skipped."""
    rows = [
        {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [
                {"name": "emotet", "malware_types": ["trojan"]},
                {"name": "qakbot", "malware_types": ["trojan"]},
                {"name": "trickbot", "malware_types": ["trojan"]},
            ],
            "vulns": [{"cve_id": "CVE-2021-44228"}],
            "techniques": [{"mitre_id": "T1059", "name": "CLI"}, {"mitre_id": "T1055", "name": "Injection"}],
            "sectors": [{"name": "energy"}],
        }
    ]
    client = _mk_client(rows)
    StixExporter(client).export_indicator("1.2.3.4")
    session = client.driver._session
    aggregate_calls = session.aggregate_calls
    labels = [_aggregate_label(c) for c, _ in aggregate_calls]
    assert sorted(labels) == ["Indicator", "Malware", "Technique", "Vulnerability"], labels
    assert len(labels) == len(set(labels)), "one aggregate query per label"
    # 1 export query + 4 aggregate queries — eight nodes, not eight queries.
    assert len(session.call_history) == 1 + 4
    for cypher, params in aggregate_calls:
        assert "UNWIND $rows AS row" in cypher
        assert "SOURCED_FROM" in cypher
        assert isinstance(params["rows"], list) and params["rows"]
    malware_rows = next(p["rows"] for c, p in aggregate_calls if "(n:Malware)" in c)
    assert sorted(r["name"] for r in malware_rows) == ["emotet", "qakbot", "trickbot"]
    technique_rows = next(p["rows"] for c, p in aggregate_calls if "(n:Technique)" in c)
    assert sorted(r["mitre_id"] for r in technique_rows) == ["T1055", "T1059"]


def test_batched_aggregates_are_mapped_back_to_the_right_node():
    """Rows of the batched aggregate query are keyed by the natural-key
    columns; each node must receive its own MIN/MAX, not a neighbour's."""
    rows = [
        {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [
                {"name": "emotet", "malware_types": ["trojan"]},
                {"name": "qakbot", "malware_types": ["trojan"]},
            ],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    aggregates = {
        "Malware": [
            {
                "name": "qakbot",
                "first_seen_at_source": "2019-03-01T00:00:00+00:00",
                "last_seen_at_source": "2024-05-01T00:00:00+00:00",
            },
            {
                "name": "emotet",
                "first_seen_at_source": "2014-06-01T00:00:00+00:00",
                "last_seen_at_source": "2024-01-01T00:00:00+00:00",
            },
        ],
        "Indicator": [
            {
                "indicator_type": "ipv4",
                "value": "1.2.3.4",
                "first_seen_at_source": "2023-01-01T00:00:00+00:00",
                "last_seen_at_source": "2023-02-01T00:00:00+00:00",
            }
        ],
    }
    client = _mk_client(rows, aggregate_rows_by_label=aggregates)
    bundle = StixExporter(client).export_indicator("1.2.3.4")
    by_name = {m["name"]: m for m in _by_type(bundle, "malware")}
    assert by_name["emotet"]["x_edgeguard_first_seen_at_source"].startswith("2014-06-01")
    assert by_name["qakbot"]["x_edgeguard_first_seen_at_source"].startswith("2019-03-01")
    assert by_name["qakbot"]["x_edgeguard_last_seen_at_source"].startswith("2024-05-01")
    indicator = _by_type(bundle, "indicator")[0]
    assert indicator["valid_from"].startswith("2023-01-01")
    assert "x_edgeguard_first_seen_inferred" not in indicator
    # Still one aggregate query per label.
    assert sorted(_aggregate_label(c) for c, _ in client.driver._session.aggregate_calls) == ["Indicator", "Malware"]


def test_actor_lookup_is_case_insensitive_and_alias_aware():
    """Actor names are stored lower-case; the lookup must fold the input
    and each alias with ``toLower(trim(...))`` exactly like
    ``GET /actors/{name}/summary`` — a case-sensitive ``a.name = $name``
    never matches ``APT28`` against the stored ``apt28``."""
    client = _mk_client([_ACTOR_ROW])
    StixExporter(client).export_threat_actor("APT28")
    q = client.driver._session.main_cypher
    assert "a.name = toLower(trim($name))" in q
    assert "any(x IN coalesce(a.aliases, []) WHERE toLower(trim(x)) = toLower(trim($name)))" in q
    assert "a.name = $name" not in q
    assert "$name IN coalesce(a.aliases, [])" not in q
    # The raw input is bound as a parameter; folding happens in Cypher.
    assert client.driver._session.main_params["name"] == "APT28"


# The bounds below are applied inside the Cypher, which the fake driver
# cannot execute; these tests pin the statement shape that prevents the
# defect and exercise the Python side with rows in the problematic order.
# The statements themselves are validated with EXPLAIN against a live
# Neo4j as part of the review process.


def test_actor_malware_technique_pairs_bounded_without_null_rows():
    """Malware without IMPLEMENTS_TECHNIQUE edges must not consume slots of
    the malware → technique bound: the pairs are produced by a plain
    ``MATCH`` inside a ``CALL`` subquery (no ``OPTIONAL MATCH`` null rows,
    no ``[null]`` padding) that is ordered and limited before it is
    collected, and the aggregating ``RETURN`` keeps the outer row alive
    when no pair exists."""
    rows = [
        {
            "seed": {"name": "apt28"},
            # ``a-no-tech`` sorts before ``b-with-tech`` by name and has no
            # technique; the only pair belongs to the second malware.
            "malware": [{"name": "a-no-tech"}, {"name": "b-with-tech"}],
            "actor_tech": [],
            "mal_tech": [{"m": {"name": "b-with-tech"}, "t": {"mitre_id": "T1059", "name": "CLI"}}],
            "campaigns": [],
        }
    ]
    client = _mk_client(rows)
    bundle = StixExporter(client).export_threat_actor("APT28", limit=1)
    q = client.driver._session.main_cypher
    start = q.index("CALL (malware) {")
    end = q.index("OPTIONAL MATCH (a)-[r4:RUNS]->(c:Campaign)", start)
    subquery = q[start:end]
    assert subquery.rstrip().endswith("}"), subquery
    assert "UNWIND malware AS m_pair" in subquery and "WITH m_pair.n AS m_each" in subquery
    assert "WHERE m_each IS NOT NULL" in subquery
    assert "MATCH (m_each)-[r3:IMPLEMENTS_TECHNIQUE]->(mt:Technique)" in subquery
    assert "OPTIONAL MATCH (m_each)" not in q
    assert "[null]" not in q
    limited = [line for line in subquery.splitlines() if "LIMIT $limit" in line]
    assert len(limited) == 1 and "ORDER BY m_each.name, mt.mitre_id" in limited[0]
    assert "RETURN collect({m: m_each, t: mt, r: properties(r3)}) AS mal_tech" in subquery
    # The pair that survives the bound is exported as malware uses attack-pattern.
    rels = _by_type(bundle, "relationship")
    pair = [
        r for r in rels if r["source_ref"].startswith("malware--") and r["target_ref"].startswith("attack-pattern--")
    ]
    assert len(pair) == 1
    assert pair[0]["source_ref"] == _deterministic_id("malware", "b-with-tech")
    assert pair[0]["relationship_type"] == "uses"


def test_indicator_export_dedupes_cve_twins_before_limit():
    """Twin ``CVE`` / ``Vulnerability`` nodes share a cve_id (and a STIX
    id). The EXPLOITS stage must keep one node per cve_id — the ``CVE``
    twin when present — BEFORE ``LIMIT $limit``, so twins do not take two
    slots and the surviving twin is deterministic."""
    rows = [
        {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [],
            "vulns": [{"cve_id": "CVE-2021-44228", "severity": "CRITICAL"}, {"cve_id": "CVE-2021-44228"}],
            "techniques": [],
            "sectors": [],
        }
    ]
    client = _mk_client(rows)
    bundle = StixExporter(client).export_indicator("1.2.3.4")
    q = client.driver._session.main_cypher
    prefer = q.index("WITH i, malware, v, r2 ORDER BY (CASE WHEN v:CVE THEN 0 ELSE 1 END)")
    dedupe = q.index("WITH i, malware, v.cve_id AS cve_key, head(collect(v)) AS vn, collect(properties(r2)) AS r2s")
    bound = q.index("WITH i, malware, {n: vn, r: r2s} AS vr ORDER BY vr.n.cve_id LIMIT $limit")
    collect = q.index("WITH i, malware, collect(vr) AS vulns")
    assert prefer < dedupe < bound < collect
    # Twins returned by the driver still collapse to one vulnerability SDO.
    vulns = _by_type(bundle, "vulnerability")
    assert len(vulns) == 1
    assert vulns[0]["id"] == _deterministic_id("vulnerability", "CVE-2021-44228")


def test_cve_export_walks_both_twins_and_aggregates_either_label():
    """The CVE seed takes its properties from the CVE-preferred twin but
    walks EXPLOITS and AFFECTS from every node sharing the cve_id, so
    edges attached only to the ``Vulnerability`` twin enter the bundle;
    rows without a match sort last so they never displace neighbours. The
    source-aggregate prefetch matches either label and groups by cve_id,
    so a CVE-only seed still receives its SOURCED_FROM timestamps."""
    rows = [
        {
            "seed": {"cve_id": "CVE-2021-44228", "severity": "CRITICAL"},
            "indicators": [{"value": "evil.example", "indicator_type": "domain"}],
            "sectors": [{"name": "energy"}],
        }
    ]
    aggregates = {
        "Vulnerability": [
            {
                "cve_id": "CVE-2021-44228",
                "first_seen_at_source": "2021-12-10T00:00:00+00:00",
                "last_seen_at_source": "2024-01-05T00:00:00+00:00",
            }
        ]
    }
    client = _mk_client(rows, aggregate_rows_by_label=aggregates)
    bundle = StixExporter(client).export_cve("CVE-2021-44228")
    q = client.driver._session.main_cypher
    # Seed folding: one row, CVE-preferred head, every twin kept.
    assert "LIMIT 1" not in q
    fold = q.index("WITH head(collect(v)) AS seed, collect(v) AS twins")
    exploits = q.index("OPTIONAL MATCH (i:Indicator)-[r1:EXPLOITS]->(tw)")
    threats = q.index("OPTIONAL MATCH (x)-[r2:EXPLOITS]->(tw)")
    affects = q.index("OPTIONAL MATCH (tw)-[r3:AFFECTS]->(s:Sector)")
    assert fold < exploits < threats < affects
    assert q.count("UNWIND twins AS tw") == 3
    # One row per neighbour before each bound (its edges to both twins folded), nulls last.
    assert "WITH seed, twins, i, collect(properties(r1)) AS r1s\n" in q
    assert "ORDER BY (CASE WHEN i IS NULL THEN 1 ELSE 0 END), i.value, i.indicator_type LIMIT $limit" in q
    assert "WITH seed, twins, indicators, x, collect(properties(r2)) AS r2s\n" in q
    assert "WITH seed, indicators, threats, s, collect(properties(r3)) AS r3s\n" in q
    assert "ORDER BY (CASE WHEN s IS NULL THEN 1 ELSE 0 END), s.name LIMIT $limit" in q
    assert "WITH DISTINCT" not in q
    assert "RETURN seed," in q
    # Aggregate prefetch for the seed matches either twin label.
    vuln_aggregate = next(
        c for c, _ in client.driver._session.aggregate_calls if _aggregate_label(c) == "Vulnerability"
    )
    assert "MATCH (n) WHERE (n:CVE OR n:Vulnerability) AND n.`cve_id` = row.`cve_id`" in vuln_aggregate
    assert "MATCH (n:Vulnerability)" not in vuln_aggregate
    assert "RETURN n.`cve_id` AS `cve_id`" in vuln_aggregate
    seed_sdo = _by_type(bundle, "vulnerability")[0]
    assert seed_sdo["x_edgeguard_first_seen_at_source"].startswith("2021-12-10")
    assert seed_sdo["x_edgeguard_last_seen_at_source"].startswith("2024-01-05")
    assert seed_sdo["x_edgeguard_severity"] == "CRITICAL"


def test_default_tlp_marking_warns_once_when_config_unreadable(monkeypatch, caplog):
    """When ``config`` cannot be imported the default falls back to
    TLP:WHITE and says so — once per process, not once per node."""
    monkeypatch.setattr(stix_exporter, "_TLP_DEFAULT_WARNED", False)
    monkeypatch.setitem(sys.modules, "config", None)  # ``import config`` raises ImportError
    with caplog.at_level("WARNING", logger="stix_exporter"):
        assert stix_exporter._default_tlp_marking_id() == _TLP_SPEC_IDS["white"]
        assert stix_exporter._default_tlp_marking_id() == _TLP_SPEC_IDS["white"]
    warnings = [r for r in caplog.records if "Deployment default TLP" in r.message]
    assert len(warnings) == 1, [r.message for r in caplog.records]
    assert "configuration could not be read" in warnings[0].message
    assert "TLP:WHITE applied" in warnings[0].message


def test_default_tlp_marking_warns_when_configured_level_unknown(monkeypatch, caplog):
    """A configured ``EDGEGUARD_DEFAULT_TLP`` outside the TLP ladder is not
    silently replaced: TLP:WHITE is applied and a warning names the level."""
    import config

    monkeypatch.setattr(stix_exporter, "_TLP_DEFAULT_WARNED", False)
    monkeypatch.setattr(config, "EDGEGUARD_DEFAULT_TLP", "purple")
    with caplog.at_level("WARNING", logger="stix_exporter"):
        assert stix_exporter._default_tlp_marking_id() == _TLP_SPEC_IDS["white"]
    warnings = [r for r in caplog.records if "Deployment default TLP" in r.message]
    assert len(warnings) == 1
    assert "'purple'" in warnings[0].message


# ---------------------------------------------------------------------------
# Export hardening (2026-10): TLP markings, strict parsing, patterns, SROs
# ---------------------------------------------------------------------------

_TLP_SPEC_IDS = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def test_tlp_marking_objects_present_and_referenced():
    """Every SDO carries ``object_marking_refs`` from the node's ``tlp``;
    the referenced TLP ``marking-definition`` objects (the fixed STIX 2.1
    identifiers) are included in the bundle; SROs inherit the most
    restrictive marking of their endpoints."""
    rows = [
        {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4", "tlp": "amber"},
            "malware": [{"name": "emotet", "malware_types": ["trojan"], "tlp": "green"}],
            "vulns": [{"cve_id": "CVE-2021-44228", "tlp": "red"}],
            "techniques": [{"mitre_id": "T1059", "name": "CLI"}],  # no TLP → deployment default (white)
            "sectors": [],
        }
    ]
    bundle = StixExporter(_mk_client(rows)).export_indicator("1.2.3.4")
    assert _by_type(bundle, "indicator")[0]["object_marking_refs"] == [_TLP_SPEC_IDS["amber"]]
    assert _by_type(bundle, "malware")[0]["object_marking_refs"] == [_TLP_SPEC_IDS["green"]]
    assert _by_type(bundle, "vulnerability")[0]["object_marking_refs"] == [_TLP_SPEC_IDS["red"]]
    assert _by_type(bundle, "attack-pattern")[0]["object_marking_refs"] == [_TLP_SPEC_IDS["white"]]
    markings = {m["id"]: m for m in _by_type(bundle, "marking-definition")}
    referenced = {ref for o in bundle["objects"] for ref in o.get("object_marking_refs", [])}
    assert set(markings) == referenced == set(_TLP_SPEC_IDS.values())
    for m in markings.values():
        assert m["definition_type"] == "tlp"
        assert m["created"] == "2017-01-20T00:00:00.000Z"
    # SRO marking = most restrictive endpoint.
    rels = {r["target_ref"].split("--")[0]: r for r in _by_type(bundle, "relationship")}
    assert rels["malware"]["object_marking_refs"] == [_TLP_SPEC_IDS["amber"]]  # amber indicator → green malware
    assert rels["vulnerability"]["object_marking_refs"] == [_TLP_SPEC_IDS["red"]]  # amber indicator → red CVE
    assert rels["attack-pattern"]["object_marking_refs"] == [_TLP_SPEC_IDS["amber"]]


def test_tlp_level_mapping_edge_cases(monkeypatch, caplog):
    """``clear`` is TLP 2.0's name for WHITE; ``amber+strict`` has no STIX
    2.1 built-in and must not be loosened (→ RED); an unrecognised level is
    exported restricted (AMBER) with a warning; a missing level follows the
    deployment default ``config.EDGEGUARD_DEFAULT_TLP``."""
    import config

    ref = stix_exporter._marking_ref_for
    assert ref({"tlp": "clear"}) == _TLP_SPEC_IDS["white"]
    assert ref({"tlp": "WHITE"}) == _TLP_SPEC_IDS["white"]
    assert ref({"tlp": "amber+strict"}) == _TLP_SPEC_IDS["red"]
    with caplog.at_level("WARNING", logger="stix_exporter"):
        assert ref({"tlp": "purple"}) == _TLP_SPEC_IDS["amber"]
    assert any("Unrecognised TLP level" in r.message for r in caplog.records)
    monkeypatch.setattr(config, "EDGEGUARD_DEFAULT_TLP", "green")
    assert ref({}) == _TLP_SPEC_IDS["green"]
    assert ref({"tlp": None}) == _TLP_SPEC_IDS["green"]
    monkeypatch.setattr(config, "EDGEGUARD_DEFAULT_TLP", "white")
    assert ref({}) == _TLP_SPEC_IDS["white"]


def _rich_indicator_rows() -> List[Dict[str, Any]]:
    """A seed with every property class the exporter can emit."""
    return [
        {
            "seed": {
                "value": "203.0.113.5",
                "indicator_type": "ipv4",
                "tlp": "amber",
                "zone": ["energy", "global"],
                "misp_event_ids": ["1001", "1002"],
                "misp_attribute_ids": ["uuid-a"],
                "first_imported_at": "2026-04-21T08:00:00+00:00",
                "last_updated": "2026-04-22T08:00:00+00:00",
            },
            "malware": [{"name": "emotet", "malware_types": ["trojan"], "tlp": "green", "zone": ["finance"]}],
            "vulns": [
                {
                    "cve_id": "CVE-2021-44228",
                    "description": "Log4Shell",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "attack_vector": "NETWORK",
                    "published": "2021-12-10T10:15:09+00:00",
                    "last_modified": "2024-01-05T00:00:00+00:00",
                    "cisa_exploit_add": "2021-12-10",
                    "cisa_action_due": "2021-12-24",
                    "cisa_required_action": "Apply updates per vendor instructions.",
                    "cisa_vulnerability_name": "Apache Log4j2 Remote Code Execution Vulnerability",
                    "cwe": ["CWE-917"],
                    "cisa_cwes": ["CWE-917"],
                    "ref_tags": ["Exploit"],
                    "reference_urls": ["https://logging.apache.org/log4j/2.x/security.html"],
                    "affected_products": ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
                    "tlp": "white",
                }
            ],
            "techniques": [
                {"mitre_id": "T1059", "name": "Command and Scripting Interpreter", "tactic_phases": ["execution"]}
            ],
            "sectors": [{"name": "energy"}],
        }
    ]


def _rich_aggregates() -> Dict[str, List[Dict[str, Any]]]:
    return {
        "Indicator": [
            {
                "indicator_type": "ipv4",
                "value": "203.0.113.5",
                "first_seen_at_source": "2023-01-01T00:00:00+00:00",
                "last_seen_at_source": "2023-02-01T00:00:00+00:00",
            }
        ]
    }


def test_rich_bundle_passes_strict_stix2_parse(monkeypatch):
    """The bundle must parse with ``stix2.parse`` under the default
    ``allow_custom=False`` while keeping the provenance and every
    ``x_edgeguard_*`` property. Negative control: removing the extension
    declaration from one object makes the same bundle fail, which proves
    the parser is strict and the extension is what makes it acceptable."""
    monkeypatch.setattr(stix_exporter, "_GIT_SHA", "d5dc41f")
    bundle = StixExporter(_mk_client(_rich_indicator_rows(), _rich_aggregates())).export_indicator("203.0.113.5")

    parsed = stix2.parse(bundle)  # allow_custom defaults to False
    assert parsed.type == "bundle"
    assert len(parsed.objects) == len(bundle["objects"])

    # Provenance and extension properties survived at the top level.
    indicator = _by_type(bundle, "indicator")[0]
    assert indicator["x_edgeguard_zones"] == ["energy", "global"]
    assert indicator["x_edgeguard_misp_event_ids"] == ["1001", "1002"]
    assert indicator["x_edgeguard_first_seen_at_source"].startswith("2023-01-01")
    assert indicator["x_edgeguard_first_imported_at"].startswith("2026-04-21")
    assert _by_type(bundle, "vulnerability")[0]["x_edgeguard_cvss_score"] == 10.0
    assert _producer_identity(bundle)["x_edgeguard_git_sha"] == "d5dc41f"
    assert indicator["extensions"] == {EDGEGUARD_EXTENSION_ID: {"extension_type": "toplevel-property-extension"}}

    # Negative control: the bare x_ properties are rejected without the extension.
    import copy

    broken = copy.deepcopy(bundle)
    next(o for o in broken["objects"] if o["type"] == "indicator").pop("extensions")
    with pytest.raises(Exception) as excinfo:
        stix2.parse(broken)
    assert "x_edgeguard_" in str(excinfo.value)


def test_every_emitted_extension_property_is_declared():
    """``extension_properties`` of the extension definition must list every
    ``x_edgeguard_*`` property the exporter emits — a strict consumer that
    validates against the declaration would otherwise reject the object."""
    bundle = StixExporter(_mk_client(_rich_indicator_rows(), _rich_aggregates())).export_indicator("203.0.113.5")
    ext_def = next(o for o in bundle["objects"] if o["type"] == "extension-definition")
    assert ext_def["id"] == EDGEGUARD_EXTENSION_ID
    assert ext_def["created_by_ref"] == EDGEGUARD_IDENTITY_ID
    assert ext_def["extension_types"] == ["toplevel-property-extension"]
    declared = set(ext_def["extension_properties"])
    emitted = {k for o in bundle["objects"] for k in o if k.startswith("x_edgeguard_")}
    # Non-vacuous: the fixture exercises timestamps, zones, MISP ids, NVD
    # and CISA enrichment and the identity provenance.
    assert len(emitted) >= 15, sorted(emitted)
    assert emitted <= declared, sorted(emitted - declared)
    # Objects with extension properties declare the extension; objects
    # without them do not grow an ``extensions`` map.
    for o in bundle["objects"]:
        has_ext_props = any(k.startswith("x_edgeguard_") for k in o)
        assert has_ext_props == (EDGEGUARD_EXTENSION_ID in o.get("extensions", {})), o["id"]


def test_a_rejected_cve_exports_its_status_and_parses_strictly():
    """``CVE.status`` (NVD's record status, written by ``merge_cve`` since 2026-10) is exported as
    ``x_edgeguard_status``; before, a rejected CVE exported like an active one. Real record: NVD's
    CVE-2026-22314, rejected (``tests/fixtures/nvd_incremental_2026_10_14.json``)."""
    import json
    from pathlib import Path

    fixtures = json.loads(
        (Path(__file__).resolve().parent / "fixtures" / "nvd_incremental_2026_10_14.json").read_text()
    )
    record = fixtures["nvd"]["CVE-2026-22314"]["cve"]
    assert record["vulnStatus"] == "Rejected"
    seed = {
        "cve_id": "CVE-2026-22314",
        "description": next(d["value"] for d in record["descriptions"] if d["lang"] == "en"),
        "status": ["rejected"],
        "edgeguard_managed": True,
    }
    rows = [{"seed": seed, "indicators": [], "threats": [], "sectors": []}]
    bundle = StixExporter(_mk_client(rows)).export_cve("CVE-2026-22314")

    (vulnerability,) = _by_type(bundle, "vulnerability")
    assert vulnerability["x_edgeguard_status"] == ["rejected"]
    assert vulnerability["extensions"] == {EDGEGUARD_EXTENSION_ID: {"extension_type": "toplevel-property-extension"}}
    definition = next(o for o in bundle["objects"] if o["type"] == "extension-definition")
    assert "x_edgeguard_status" in definition["extension_properties"]
    assert (definition["version"], definition["modified"][:10]) == ("1.4.0", "2026-10-15")
    parsed = stix2.parse(bundle)  # strict: allow_custom defaults to False
    assert next(o for o in parsed.objects if o.type == "vulnerability")["x_edgeguard_status"] == ["rejected"]


def test_vulnerability_exports_epss_and_cisa_ssvc():
    """2026-10: FIRST EPSS (``enrich_cve_epss``) and CISA's SSVC decision points (from NVD's record)
    reach the ``vulnerability`` as declared extension properties (definition 1.4.0); ``epss_updated_at``
    is EdgeGuard's write time, not data, and stays in the graph."""
    seed = {
        "cve_id": "CVE-2021-44228",
        "edgeguard_managed": True,
        "epss_score": 0.97565,
        "epss_percentile": 0.99999,
        "epss_score_date": "2026-10-11T12:00:25Z",
        "epss_model_version": "v2026.06.15",
        "epss_updated_at": "2026-10-15T08:00:00Z",
        "ssvc_exploitation": "active",
        "ssvc_automatable": "yes",
        "ssvc_technical_impact": "total",
        "ssvc_version": "2.0.3",
        "ssvc_timestamp": "2025-02-04T14:25:34.416117Z",
    }
    rows = [{"seed": seed, "indicators": [], "threats": [], "sectors": []}]
    bundle = StixExporter(_mk_client(rows)).export_cve("CVE-2021-44228")
    (vulnerability,) = _by_type(bundle, "vulnerability")
    expected = {f"x_edgeguard_{key}": value for key, value in seed.items() if key.startswith(("epss_", "ssvc_"))}
    del expected["x_edgeguard_epss_updated_at"]
    assert {
        k: v for k, v in vulnerability.items() if k.startswith(("x_edgeguard_epss", "x_edgeguard_ssvc"))
    } == expected
    definition = next(o for o in bundle["objects"] if o["type"] == "extension-definition")
    assert set(expected) <= set(definition["extension_properties"])
    stix2.parse(bundle)  # strict: every emitted property is declared


def test_x_mitre_tactic_is_the_only_remaining_custom_type():
    """Document the known exception: ``_tactic_sdo`` keeps MITRE's
    ``x-mitre-tactic`` custom type (not strictly parseable) and no
    ``export_*`` path reaches it."""
    exporter = StixExporter(_mk_client([]))
    sdo = exporter._tactic_sdo({"mitre_id": "TA0002", "name": "Execution"})
    assert sdo["type"] == "x-mitre-tactic"
    assert sdo["created_by_ref"] == EDGEGUARD_IDENTITY_ID
    assert sdo["object_marking_refs"] == [_TLP_SPEC_IDS["white"]]
    src = open(stix_exporter.__file__, encoding="utf-8").read()
    export_bodies = src.split("    def export_")[1:]
    assert export_bodies and not any('"Tactic"' in body.split("    def _")[0] for body in export_bodies)


_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_SHA512 = _SHA256 + _SHA256


@pytest.mark.parametrize(
    "indicator_type, value, expected",
    [
        ("email", "alice@example.com", "[email-addr:value = 'alice@example.com']"),
        ("email-src", "bob@example.com", "[email-addr:value = 'bob@example.com']"),
        ("hash", _MD5, f"[file:hashes.'MD5' = '{_MD5}']"),
        ("hash", _SHA1, f"[file:hashes.'SHA-1' = '{_SHA1}']"),
        ("hash", _SHA256, f"[file:hashes.'SHA-256' = '{_SHA256}']"),
        ("hash", _SHA512, f"[file:hashes.'SHA-512' = '{_SHA512}']"),
        ("hash", _SHA256.upper(), f"[file:hashes.'SHA-256' = '{_SHA256.upper()}']"),
        ("md5", _MD5, f"[file:hashes.'MD5' = '{_MD5}']"),
        ("sha256", _SHA256, f"[file:hashes.'SHA-256' = '{_SHA256}']"),
        # Declared type contradicted by the digest format: the format decides.
        ("md5", _SHA256, f"[file:hashes.'SHA-256' = '{_SHA256}']"),
        (
            "hash",
            "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",
            "[file:hashes.'SSDEEP' = '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C']",
        ),
        # No algorithm fits: a custom key rather than a wrong label.
        ("hash", "abc123", "[file:hashes.'UNKNOWN' = 'abc123']"),
        ("url", "http://evil.example/a'b\\c", "[url:value = 'http://evil.example/a\\'b\\\\c']"),
        ("domain", "evil.example", "[domain-name:value = 'evil.example']"),
        ("hostname", "host.evil.example", "[domain-name:value = 'host.evil.example']"),
        ("ipv4", "203.0.113.5", "[ipv4-addr:value = '203.0.113.5']"),
        ("ipv4", "203.0.113.0/24", "[ipv4-addr:value = '203.0.113.0/24']"),
        ("ipv6", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
        ("filename", "payload.exe", "[file:name = 'payload.exe']"),
        # Blank type: inferred from the value's shape.
        ("", "203.0.113.9", "[ipv4-addr:value = '203.0.113.9']"),
        ("", _SHA1, f"[file:hashes.'SHA-1' = '{_SHA1}']"),
        # Nothing fits: a custom observable type, never a non-base64 payload_bin.
        ("unknown", "just a phrase", "[x-edgeguard-observable:value = 'just a phrase']"),
    ],
)
def test_build_pattern_grammar(indicator_type, value, expected):
    pattern = _build_pattern(indicator_type, value)
    assert pattern == expected
    assert "payload_bin" not in pattern
    # The stix2 pattern validator accepts it (it rejects digests whose
    # format does not match the declared algorithm).
    stix2.Indicator(pattern=pattern, pattern_type="stix", valid_from="2026-01-01T00:00:00Z")


def test_indicator_sdo_patterns_are_valid_for_email_and_hash_nodes():
    """End-to-end through ``_indicator_sdo``: e-mail and hash indicators no
    longer fall through to ``artifact:payload_bin``."""
    exporter = StixExporter(_mk_client([]))
    email = exporter._indicator_sdo({"value": "alice@example.com", "indicator_type": "email"})
    assert email["pattern"] == "[email-addr:value = 'alice@example.com']"
    digest = exporter._indicator_sdo({"value": _SHA256, "indicator_type": "hash"})
    assert digest["pattern"] == f"[file:hashes.'SHA-256' = '{_SHA256}']"


def test_edge_to_sro_follows_the_stix21_relationship_table():
    """Each graph edge maps to the relationship_type the STIX 2.1 summary
    table permits for the (source, target) pair; the table-defined pairs
    that run the other way are reversed; unknown pairs → related-to."""
    exporter = StixExporter(_mk_client([]))
    ind = _deterministic_id("indicator", "ipv4|1.2.3.4")
    mal = _deterministic_id("malware", "emotet")
    vuln = _deterministic_id("vulnerability", "CVE-2021-44228")
    ident = _deterministic_id("identity", "energy")
    iset = _deterministic_id("intrusion-set", "apt28")
    camp = _deterministic_id("campaign", "pawn storm")
    ap = _deterministic_id("attack-pattern", "T1059")
    tool = _deterministic_id("tool", "mimikatz")

    def sro(edge, s, t):
        r = exporter._edge_to_sro(edge, s, t)
        return r["relationship_type"], r["source_ref"], r["target_ref"]

    assert sro("INDICATES", ind, mal) == ("indicates", ind, mal)
    assert sro("USES_TECHNIQUE", ind, ap) == ("indicates", ind, ap)
    assert sro("EXPLOITS", ind, vuln) == ("related-to", ind, vuln)
    assert sro("TARGETS", ind, ident) == ("related-to", ind, ident)
    assert sro("ATTRIBUTED_TO", mal, iset) == ("uses", iset, mal)
    assert sro("EMPLOYS_TECHNIQUE", iset, ap) == ("uses", iset, ap)
    assert sro("IMPLEMENTS_TECHNIQUE", mal, ap) == ("uses", mal, ap)
    assert sro("IMPLEMENTS_TECHNIQUE", tool, ap) == ("uses", tool, ap)
    assert sro("RUNS", iset, camp) == ("attributed-to", camp, iset)
    assert sro("AFFECTS", vuln, ident) == ("related-to", vuln, ident)
    # Unknown pair: graph direction kept, related-to.
    assert sro("SOMETHING_NEW", tool, ident) == ("related-to", tool, ident)
    r = exporter._edge_to_sro("INDICATES", ind, mal)
    assert r["created_by_ref"] == EDGEGUARD_IDENTITY_ID
    assert r["object_marking_refs"]


def test_actor_bundle_relationship_types_are_valid_for_their_pairs():
    """End to end: a full actor bundle emits only table-permitted
    relationship types per source type (campaign attributed-to
    intrusion-set, intrusion-set / malware uses ...)."""
    rows = [
        {
            "seed": {"name": "apt28"},
            "malware": [{"name": "x-agent", "malware_types": ["trojan"]}],
            "actor_tech": [{"mitre_id": "T1055", "name": "Process Injection"}],
            "mal_tech": [{"m": {"name": "x-agent"}, "t": {"mitre_id": "T1059", "name": "CLI"}}],
            "campaigns": [{"name": "pawn storm"}],
        }
    ]
    bundle = StixExporter(_mk_client(rows)).export_threat_actor("APT28")
    rels = _by_type(bundle, "relationship")
    assert len(rels) == 4
    pairs = {(r["source_ref"].split("--")[0], r["relationship_type"], r["target_ref"].split("--")[0]) for r in rels}
    assert pairs == {
        ("intrusion-set", "uses", "malware"),
        ("intrusion-set", "uses", "attack-pattern"),
        ("malware", "uses", "attack-pattern"),
        ("campaign", "attributed-to", "intrusion-set"),
    }


def test_sector_identity_uses_industry_sector_ov():
    """``sectors`` must hold ``industry-sector-ov`` values; the EdgeGuard
    zone stays the identity ``name``. ``global`` (the no-sector marker)
    and unknown zones carry no ``sectors``."""
    exporter = StixExporter.__new__(StixExporter)
    assert exporter._sector_sdo({"name": "finance"})["sectors"] == ["financial-services"]
    assert exporter._sector_sdo({"name": "energy"})["sectors"] == ["energy"]
    assert exporter._sector_sdo({"name": "Healthcare"})["sectors"] == ["healthcare"]
    assert exporter._sector_sdo({"name": "finance"})["name"] == "finance"
    assert "sectors" not in exporter._sector_sdo({"name": "global"})
    assert "sectors" not in exporter._sector_sdo({"name": "space-tourism"})
    assert exporter._sector_sdo({"name": "finance"})["created_by_ref"] == EDGEGUARD_IDENTITY_ID


# ---------------------------------------------------------------------------
# REST route: ``?limit=`` validation
# ---------------------------------------------------------------------------


def _api_client(monkeypatch):
    """``query_api`` module + test client with API-key enforcement disabled.

    Other test modules set ``query_api._API_KEY`` for the process; the
    established pattern (tests/test_api_hardening_partner_surface.py) is to
    neutralise it per test so the routes are exercised unauthenticated.
    """
    from fastapi.testclient import TestClient

    import query_api

    monkeypatch.setattr(query_api, "_API_KEY", None)
    return query_api, TestClient(query_api.app)


def test_route_limit_constants_match_exporter(monkeypatch):
    query_api, _client = _api_client(monkeypatch)
    assert query_api._STIX_DEFAULT_LIMIT == stix_exporter._DEFAULT_LIMIT == 100
    assert query_api._STIX_MAX_LIMIT == stix_exporter._MAX_LIMIT == 500


def test_route_limit_default_and_explicit_value_reach_the_query(monkeypatch):
    query_api, http = _api_client(monkeypatch)
    neo4j_client = _mk_client([_TECHNIQUE_ROW])
    monkeypatch.setattr(query_api, "neo4j_client", neo4j_client)

    resp = http.get("/stix/export/technique/T1059")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("application/stix+json")
    assert neo4j_client.driver._session.main_params["limit"] == 100

    neo4j_client = _mk_client([_TECHNIQUE_ROW])
    monkeypatch.setattr(query_api, "neo4j_client", neo4j_client)
    resp = http.get("/stix/export/technique/T1059?limit=500")
    assert resp.status_code == 200, resp.text
    assert neo4j_client.driver._session.main_params["limit"] == 500

    neo4j_client = _mk_client([_TECHNIQUE_ROW])
    monkeypatch.setattr(query_api, "neo4j_client", neo4j_client)
    resp = http.get("/stix/export/technique/T1059?limit=7")
    assert resp.status_code == 200, resp.text
    assert neo4j_client.driver._session.main_params["limit"] == 7


@pytest.mark.parametrize("bad", ["0", "-1", "501", "abc", "1.5"])
def test_route_limit_out_of_range_is_rejected_with_422(monkeypatch, bad):
    query_api, http = _api_client(monkeypatch)
    neo4j_client = _mk_client([_TECHNIQUE_ROW])
    monkeypatch.setattr(query_api, "neo4j_client", neo4j_client)
    resp = http.get(f"/stix/export/technique/T1059?limit={bad}")
    assert resp.status_code == 422, resp.text
    assert neo4j_client.driver._session.call_history == [], "no query must run for an invalid limit"


def test_stix_types_advertises_limit_bounds(monkeypatch):
    _query_api, http = _api_client(monkeypatch)
    resp = http.get("/stix/types")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["default_limit"] == 100
    assert data["max_limit"] == 500
