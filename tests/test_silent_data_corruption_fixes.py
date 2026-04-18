"""PR #37 regression pins for the silent-data-corruption fixes batch.

This file groups the structural pins for four independent fixes that
landed together in PR #37 because they share a theme: "graph state
silently drifts from reality, no errors, no logs". Each pin would
catch a future refactor that re-introduced the bug.

Fixes pinned here:

1. **STIX bundle determinism** (Devil's Advocate + Logic Tracker
   Tier S, both flagged independently): bundle.id must be a stable
   uuid5 of the sorted-id content hash; objects[] must be sorted;
   the wall-clock timestamp must drop out when
   EDGEGUARD_DETERMINISTIC_BUNDLE is set.

2. **Sector edgeguard_managed=true stamp** (Devil's Advocate Tier S):
   build_relationships 7a/7b auto-create Sector nodes; without the
   stamp, STIX exporter's WHERE filter drops them silently from
   every bundle.

3. **Indicator/Malware/ThreatActor case canonicalization** (Logic
   Tracker Tier S): MERGE keys must be lowercased + NFC-normalized
   for case-insensitive types so "TrickBot"/"trickbot"/"Trickbot"
   merge into a single node instead of three nodes-sharing-one-uuid.

4. **Null-key MERGE refusal** (Bug Hunter Tier S A3):
   merge_ip(None) / merge_host(None) /
   merge_resilmesh_vulnerability(no cve_id) must REFUSE rather
   than collapse all unknown rows onto one sentinel node.
"""

from __future__ import annotations

import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# 1. STIX bundle determinism
# ---------------------------------------------------------------------------


def test_stix_bundle_id_is_deterministic_for_same_object_ids():
    """Two _bundle() calls with the same object IDs (in any order) must
    produce the same bundle.id. Pins the contract so a future refactor
    can't silently re-introduce uuid.uuid4() (which would defeat
    ResilMesh's bundle-diff workflow)."""
    from stix_exporter import StixExporter

    # Bare instance — _bundle is a method but we don't need a real Neo4j client
    exporter = StixExporter(neo4j_client=None)

    objs_a = [
        {"id": "indicator--abc-123", "type": "indicator"},
        {"id": "malware--def-456", "type": "malware"},
    ]
    # Same set, opposite order
    objs_b = [
        {"id": "malware--def-456", "type": "malware"},
        {"id": "indicator--abc-123", "type": "indicator"},
    ]
    bundle_a = exporter._bundle(objs_a)
    bundle_b = exporter._bundle(objs_b)
    assert bundle_a["id"] == bundle_b["id"], (
        "bundle.id must be deterministic given the same object id set, regardless of order. "
        "If this fails, ResilMesh diff alarms fire on every poll."
    )


def test_stix_bundle_objects_are_sorted_by_id():
    """objects[] must be sorted by 'id' so byte-stable comparison works
    across Cypher row-order variations (Neo4j does NOT guarantee row
    order absent ORDER BY)."""
    from stix_exporter import StixExporter

    exporter = StixExporter(neo4j_client=None)
    objs = [
        {"id": "z--last", "type": "x"},
        {"id": "a--first", "type": "x"},
        {"id": "m--middle", "type": "x"},
    ]
    bundle = exporter._bundle(objs)
    ids = [o["id"] for o in bundle["objects"]]
    assert ids == sorted(ids), "bundle.objects must be sorted by id"


def test_stix_bundle_omits_wall_clock_when_deterministic_env_set(monkeypatch):
    """When EDGEGUARD_DETERMINISTIC_BUNDLE=1, ``generated_at`` must be
    omitted entirely so two bundles with the same content are byte-stable
    (used by ResilMesh diff polls and CI snapshot tests)."""
    from stix_exporter import StixExporter

    monkeypatch.setenv("EDGEGUARD_DETERMINISTIC_BUNDLE", "1")
    exporter = StixExporter(neo4j_client=None)
    bundle = exporter._bundle([{"id": "indicator--x", "type": "indicator"}])
    assert "generated_at" not in bundle["x_edgeguard_source"], (
        "EDGEGUARD_DETERMINISTIC_BUNDLE=1 must drop the wall-clock timestamp"
    )


def test_stix_bundle_keeps_wall_clock_by_default(monkeypatch):
    """Default ON: ``generated_at`` is present so operators can answer
    'when did this bundle leave EdgeGuard' from the bundle alone."""
    from stix_exporter import StixExporter

    monkeypatch.delenv("EDGEGUARD_DETERMINISTIC_BUNDLE", raising=False)
    exporter = StixExporter(neo4j_client=None)
    bundle = exporter._bundle([])
    assert "generated_at" in bundle["x_edgeguard_source"], "default behavior must keep generated_at for forensics"


# ---------------------------------------------------------------------------
# 2. Sector edgeguard_managed=true stamp
# ---------------------------------------------------------------------------


def test_sector_merge_in_7a_stamps_edgeguard_managed():
    """Source-grep pin: build_relationships 7a (Indicator → Sector
    TARGETS) MUST set ``sec.edgeguard_managed = true`` on the Sector
    MERGE. Without it, every STIX bundle silently drops the Sector
    SDO + the TARGETS SRO (exporter filters with WHERE
    s.edgeguard_managed = true)."""
    path = os.path.join(_SRC, "build_relationships.py")
    with open(path) as fh:
        src = fh.read()
    # Locate 7a section
    start = src.find("# 7a.")
    if start < 0:
        # Tolerate header reformatting: alternate marker
        start = src.find("Indicator → Sector (TARGETS)")
    assert start > 0, "could not locate 7a Sector merge"
    # Walk to the end of 7a (start of 7b)
    end = src.find("# 7b.", start)
    if end < 0:
        end = src.find("Vulnerability/CVE → Sector", start)
    section = src[start:end] if end > 0 else src[start : start + 2000]
    assert "edgeguard_managed = true" in section, (
        "7a Sector MERGE must set sec.edgeguard_managed = true — STIX exporter's WHERE filter drops Sectors without it"
    )


def test_sector_merge_in_7b_stamps_edgeguard_managed():
    """Same contract for 7b (Vulnerability/CVE → Sector AFFECTS)."""
    path = os.path.join(_SRC, "build_relationships.py")
    with open(path) as fh:
        src = fh.read()
    start = src.find("# 7b.")
    if start < 0:
        start = src.find("Vulnerability/CVE → Sector")
    assert start > 0, "could not locate 7b Sector merge"
    end = src.find("# 8.", start)
    if end < 0:
        end = src.find("# 8/12", start)
    section = src[start:end] if end > 0 else src[start : start + 2000]
    assert "edgeguard_managed = true" in section, "7b Sector MERGE must set sec.edgeguard_managed = true"


def test_sector_backfill_migration_exists():
    """The Sector backfill migration must exist for operators to heal
    pre-PR-#37 graphs."""
    path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "migrations",
        "2026_04_sector_edgeguard_managed_backfill.cypher",
    )
    assert os.path.exists(path), (
        "migrations/2026_04_sector_edgeguard_managed_backfill.cypher must ship — "
        "operators with pre-PR-#37 Sector nodes need it to restore STIX export"
    )
    with open(path) as fh:
        body = fh.read()
    assert "edgeguard_managed = true" in body, "backfill must set the flag"
    assert "MATCH (s:Sector)" in body, "backfill must target Sector nodes"


# ---------------------------------------------------------------------------
# 3. Indicator/Malware/ThreatActor case canonicalization
# ---------------------------------------------------------------------------


def test_canonicalize_merge_key_lowercases_malware_name():
    """Pure-function pin: ``Malware{name:"TrickBot"}`` must canonicalize
    to ``{"name": "trickbot"}``."""
    from node_identity import canonicalize_merge_key

    out = canonicalize_merge_key("Malware", {"name": "TrickBot"})
    assert out["name"] == "trickbot"


def test_canonicalize_merge_key_lowercases_threat_actor_name():
    from node_identity import canonicalize_merge_key

    out = canonicalize_merge_key("ThreatActor", {"name": "APT29"})
    assert out["name"] == "apt29"


def test_canonicalize_merge_key_lowercases_ipv4_value():
    """IPv4 — case-insensitive (well, IPv4 is digits only but canonicalize
    anyway for consistency)."""
    from node_identity import canonicalize_merge_key

    out = canonicalize_merge_key("Indicator", {"indicator_type": "ipv4", "value": "203.0.113.5"})
    assert out["value"] == "203.0.113.5"


def test_canonicalize_merge_key_lowercases_hash_value():
    """SHA256: case-insensitive per RFC + de-facto convention."""
    from node_identity import canonicalize_merge_key

    out = canonicalize_merge_key(
        "Indicator",
        {"indicator_type": "sha256", "value": "ABC123DEF456"},
    )
    assert out["value"] == "abc123def456"


def test_canonicalize_merge_key_lowercases_domain():
    from node_identity import canonicalize_merge_key

    out = canonicalize_merge_key(
        "Indicator",
        {"indicator_type": "domain", "value": "Example.COM"},
    )
    assert out["value"] == "example.com"


def test_canonicalize_merge_key_preserves_url_case():
    """URLs: PATH is case-sensitive on most servers — must NOT lowercase."""
    from node_identity import canonicalize_merge_key

    out = canonicalize_merge_key(
        "Indicator",
        {"indicator_type": "url", "value": "https://Example.com/Path/CASE_SENSITIVE"},
    )
    # Only NFC + strip applied; case preserved
    assert "CASE_SENSITIVE" in out["value"]


def test_canonicalize_merge_key_preserves_email_case():
    """Email local-part is technically case-sensitive per RFC 5321."""
    from node_identity import canonicalize_merge_key

    out = canonicalize_merge_key(
        "Indicator",
        {"indicator_type": "email", "value": "Alice@Example.com"},
    )
    assert "Alice" in out["value"]


def test_canonicalize_merge_key_strips_whitespace():
    """Trailing/leading whitespace duplicates collapse even for case-
    sensitive types (NFC + strip applied universally for indicator
    values)."""
    from node_identity import canonicalize_merge_key

    out = canonicalize_merge_key(
        "Indicator",
        {"indicator_type": "url", "value": "  https://example.com  "},
    )
    assert out["value"] == "https://example.com"


def test_canonicalize_merge_key_handles_none_value_gracefully():
    """Defensive: a None value must not crash — the dict is returned
    essentially unchanged so the downstream null-key validator can
    refuse the merge cleanly."""
    from node_identity import canonicalize_merge_key

    out = canonicalize_merge_key("Malware", {"name": None})
    # name stays None (or is absent); no exception raised
    assert "name" in out


def test_merge_malware_routes_through_canonicalize():
    """Source-grep pin: merge_malware must call canonicalize_merge_key
    BEFORE building the natural-key dict for the MERGE."""
    path = os.path.join(_SRC, "neo4j_client.py")
    with open(path) as fh:
        src = fh.read()
    start = src.find("def merge_malware")
    end = src.find("\n    def ", start + 1)
    body = src[start:end]
    assert "canonicalize_merge_key" in body, (
        "merge_malware MUST call canonicalize_merge_key — without it, "
        "TrickBot/trickbot become two nodes sharing one uuid"
    )


def test_merge_actor_routes_through_canonicalize():
    """Same contract for merge_actor."""
    path = os.path.join(_SRC, "neo4j_client.py")
    with open(path) as fh:
        src = fh.read()
    start = src.find("def merge_actor")
    end = src.find("\n    def ", start + 1)
    body = src[start:end]
    assert "canonicalize_merge_key" in body, "merge_actor MUST call canonicalize_merge_key"


# ---------------------------------------------------------------------------
# 4. Null-key MERGE refusal
# ---------------------------------------------------------------------------


def test_merge_ip_refuses_null_address():
    """merge_ip(address=None) must return False without touching Neo4j —
    otherwise all unknown-IP rows fold onto a single sentinel node."""
    from unittest.mock import MagicMock

    from neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)  # bypass __init__
    client.driver = MagicMock()
    # Should NOT call session.run; should return False
    result = client.merge_ip({"address": None})
    assert result is False
    client.driver.session.assert_not_called()


def test_merge_ip_refuses_empty_address():
    """Whitespace-only is also a refusal case."""
    from unittest.mock import MagicMock

    from neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    result = client.merge_ip({"address": "   "})
    assert result is False
    client.driver.session.assert_not_called()


def test_merge_host_refuses_null_hostname():
    from unittest.mock import MagicMock

    from neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    result = client.merge_host({"hostname": None})
    assert result is False
    client.driver.session.assert_not_called()


def test_merge_resilmesh_vulnerability_refuses_null_cve_id():
    """The CVE-0000-00000 sentinel default is GONE — caller must pass
    a real cve_id."""
    from unittest.mock import MagicMock

    from neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    # No cve_id key at all
    result = client.merge_resilmesh_vulnerability({"name": "vendor advisory"})
    assert result is False
    # Empty cve_id
    result2 = client.merge_resilmesh_vulnerability({"cve_id": "", "name": "x"})
    assert result2 is False
    # Whitespace-only cve_id
    result3 = client.merge_resilmesh_vulnerability({"cve_id": "   ", "name": "x"})
    assert result3 is False
    client.driver.session.assert_not_called()


def test_merge_resilmesh_vulnerability_no_longer_uses_cve_0000_sentinel():
    """Source-grep pin: the literal "CVE-0000-00000" must NOT appear as
    a default value in merge_resilmesh_vulnerability — that was the
    sentinel that silently collapsed unrelated rows."""
    path = os.path.join(_SRC, "neo4j_client.py")
    with open(path) as fh:
        src = fh.read()
    start = src.find("def merge_resilmesh_vulnerability")
    end = src.find("\n    def ", start + 1)
    body = src[start:end]
    # Tolerate the string appearing in a comment that documents the historical bug
    code_lines = [line for line in body.splitlines() if not line.lstrip().startswith("#")]
    code_only = "\n".join(code_lines)
    assert 'cve_id = data.get("cve_id", "CVE-0000-00000")' not in code_only, (
        "merge_resilmesh_vulnerability MUST NOT default cve_id to the CVE-0000-00000 sentinel — "
        "that pattern silently collapsed unrelated vulnerability rows onto one node"
    )
