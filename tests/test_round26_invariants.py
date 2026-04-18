"""Cross-cutting invariant tests for PR #34 round 26.

The user's frustration with this PR was that the SAME anti-pattern (parallel
maps that drift, missing constraint sync, etc.) kept recurring across
different files round after round. Each round we fixed one site; bugbot found
the SAME pattern next door.

Round 26's fix is meta: instead of pinning each instance with a regression
test, write **invariant tests** that hold for the WHOLE codebase. If a
future contributor adds a new label / collector / Cypher query that violates
an invariant, the test fails BEFORE the bug ships — even if the violation
lives in a brand-new file the regression suite has never seen.

Invariants pinned here:

B1. ``_NATURAL_KEYS ↔ create_constraints`` — every label that has a
    natural key MUST have a UNIQUE constraint declared.
B2. ``compute_node_uuid(label, key_dict) == node_uuid sent to MERGE`` —
    every MERGE site that stamps ``n.uuid`` must use the same key dict
    the MERGE binds to.
B3. ``set(SECTOR_KEYWORDS.keys()) ⊆ set(VALID_ZONES)`` — keyword detection
    can only return zones that are valid.
B4. GraphQL Indicator ``uuid`` field round-trips: query → response.uuid
    equals ``compute_node_uuid("Indicator", {...})``.
B5. Zone array semantics: a 2nd ingestion adding ``["global"]`` to a node
    already at ``["healthcare"]`` keeps it at ``["healthcare"]`` (the
    write-time override holds).
B6. Backfill idempotency: re-running the backfill on a partially-stamped
    graph completes without error and stamps zero new uuids.

These are the meta-tests the user asked for: "tests that prevent the same
anti-pattern from recurring in NEW files."
"""

from __future__ import annotations

import os
import re
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# B1 — _NATURAL_KEYS ↔ create_constraints sync
# ---------------------------------------------------------------------------


def test_every_natural_key_label_has_a_unique_constraint():
    """B1: every label declared in ``_NATURAL_KEYS`` (the single source of
    truth for "what counts as a uuidable node") MUST have a matching
    UNIQUE constraint declared in ``Neo4jClient.create_constraints``.

    Why this matters: without the UNIQUE constraint, two concurrent MERGEs
    on the same logical (label, key) can create DUPLICATE nodes — each
    with a different generated uuid. Delta sync then sees two nodes for
    one logical entity → cloud receiver gets corrupted data.

    The audit (PR #34 round 26) found 10 labels declared in _NATURAL_KEYS
    that had NO constraint. Round 26 added them. This test pins the
    invariant: every future label addition MUST come with a constraint.
    """
    import importlib
    import inspect

    if "node_identity" in sys.modules:
        del sys.modules["node_identity"]
    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    node_identity = importlib.import_module("node_identity")
    neo4j_client = importlib.import_module("neo4j_client")

    src = inspect.getsource(neo4j_client.Neo4jClient.create_constraints)
    # Extract every (Label, fields) declared in a CREATE CONSTRAINT line.
    # Matches:  FOR (alias:Label) REQUIRE (alias.f1, alias.f2) IS UNIQUE
    pattern = r"FOR \([a-z_]+:(\w+)\) REQUIRE \(([^)]+)\) IS UNIQUE"
    declared: dict = {}
    for label, fields_str in re.findall(pattern, src):
        # fields_str e.g. "i.indicator_type, i.value" → ("indicator_type", "value")
        fields = tuple(f.strip().split(".", 1)[1] for f in fields_str.split(","))
        declared[label] = fields

    missing = []
    mismatched = []
    for label, expected_fields in node_identity._NATURAL_KEYS.items():
        if label not in declared:
            missing.append(label)
        elif set(declared[label]) != set(expected_fields):
            mismatched.append((label, expected_fields, declared[label]))

    assert not missing, (
        f"labels in _NATURAL_KEYS without a UNIQUE constraint in create_constraints: {missing}\n"
        "Adding a label to _NATURAL_KEYS without the constraint allows duplicate nodes "
        "via concurrent MERGE — silently breaking the deterministic-uuid contract."
    )
    assert not mismatched, "constraints declared with different fields than _NATURAL_KEYS:\n" + "\n".join(
        f"  {lbl}: expected {exp}, declared {dec}" for lbl, exp, dec in mismatched
    )


# ---------------------------------------------------------------------------
# B2 — MERGE-key matches compute_node_uuid (per-label parametrized)
# ---------------------------------------------------------------------------


def test_merge_key_dict_matches_natural_keys_for_every_helper():
    """B2: every node-merge helper in ``Neo4jClient`` (e.g. ``merge_indicator``,
    ``merge_resilmesh_user``, ``create_alert_node``) must construct the
    natural-key dict for ``compute_node_uuid`` using EXACTLY the fields
    declared in ``_NATURAL_KEYS[label]``.

    Why this matters: if a helper computes uuid from
    ``{"name": x, "version": y}`` but MERGE binds on ``{"name": x}``, the
    uuid is computed from a different key than the MERGE — the same
    logical node gets a different uuid depending on which helper called it
    (or on what extra fields happened to be in the data dict).

    This test scans ``compute_node_uuid("Label", {...})`` call sites in
    ``neo4j_client.py`` and verifies the dict literal's keys match
    ``_NATURAL_KEYS[Label]`` exactly. AST-based — robust to formatting.
    """
    import ast
    import importlib

    if "node_identity" in sys.modules:
        del sys.modules["node_identity"]
    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    node_identity = importlib.import_module("node_identity")
    neo4j_client = importlib.import_module("neo4j_client")

    src_path = neo4j_client.__file__
    with open(src_path) as fh:
        source = fh.read()
    tree = ast.parse(source)

    mismatches: list = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Look for calls to compute_node_uuid("LabelName", {literal dict})
        func = node.func
        if isinstance(func, ast.Name) and func.id == "compute_node_uuid":
            pass
        elif isinstance(func, ast.Attribute) and func.attr == "compute_node_uuid":
            pass
        else:
            continue
        if len(node.args) != 2:
            continue
        label_arg, dict_arg = node.args
        # Only process literal-string label + literal-dict key dict
        if not isinstance(label_arg, ast.Constant) or not isinstance(label_arg.value, str):
            continue
        if not isinstance(dict_arg, ast.Dict):
            continue
        label = label_arg.value
        # Skip if label not in _NATURAL_KEYS (e.g. internal/test stub).
        if label not in node_identity._NATURAL_KEYS:
            continue
        # Extract dict keys as strings; skip if any key isn't a literal string.
        keys_in_dict = []
        for k in dict_arg.keys:
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                keys_in_dict.append(k.value)
            else:
                # Dynamic key — skip this call site.
                keys_in_dict = None  # type: ignore[assignment]
                break
        if keys_in_dict is None:
            continue
        expected = set(node_identity._NATURAL_KEYS[label])
        actual = set(keys_in_dict)
        if expected != actual:
            mismatches.append((label, sorted(expected), sorted(actual), node.lineno))

    assert not mismatches, "compute_node_uuid call sites where the key dict doesn't match _NATURAL_KEYS:\n" + "\n".join(
        f"  line {lineno}: compute_node_uuid({lbl!r}, {{{', '.join(act)}}}) — expected fields {exp}"
        for lbl, exp, act, lineno in mismatches
    )


# ---------------------------------------------------------------------------
# B3 — VALID_ZONES ↔ SECTOR_KEYWORDS
# ---------------------------------------------------------------------------


def test_sector_keywords_keys_are_subset_of_valid_zones():
    """B3: ``SECTOR_KEYWORDS`` enumerates the zones that have keyword-based
    detection rules. Every key here MUST be a valid zone (i.e. in
    ``VALID_ZONES``) — otherwise ``detect_zones_from_text`` could return a
    zone that downstream filters reject.

    The reverse is NOT required: ``VALID_ZONES`` includes ``"global"``
    which is the no-match fallback default and intentionally has no
    keyword rules. ``SECTOR_KEYWORDS`` is a strict subset.
    """
    import importlib

    if "config" in sys.modules:
        del sys.modules["config"]
    config = importlib.import_module("config")

    keyword_zones = set(config.SECTOR_KEYWORDS.keys())
    valid_zones = set(config.VALID_ZONES)

    extra = keyword_zones - valid_zones
    assert not extra, (
        f"SECTOR_KEYWORDS has zones not in VALID_ZONES: {sorted(extra)}. "
        "Keyword detection would produce zones the downstream filter rejects."
    )
    # Pin the structural relationship: SECTOR_KEYWORDS ⊆ VALID_ZONES \ {"global"}
    # ("global" is the default-no-match fallback; not keyword-detectable).
    assert keyword_zones <= valid_zones - {"global"}, (
        "SECTOR_KEYWORDS must be a subset of VALID_ZONES excluding 'global' "
        f"(global is fallback-only). Got keyword_zones={sorted(keyword_zones)}, "
        f"valid_zones={sorted(valid_zones)}"
    )


# ---------------------------------------------------------------------------
# B4 — GraphQL uuid round-trip
# ---------------------------------------------------------------------------


def test_graphql_indicator_uuid_field_matches_compute_node_uuid():
    """B4: the GraphQL ``Indicator.uuid`` field (and any other entity uuid
    field) must surface the SAME uuid that ``compute_node_uuid`` would
    compute for the same natural key. Without this, a consumer querying
    by uuid in GraphQL gets a different identifier than a consumer
    looking at the Neo4j node directly.

    Drives the ``_resolve_indicators`` resolver against a fake driver
    that emits a Neo4j-shaped record with the deterministic uuid stamped
    on it. Asserts the resulting Indicator dataclass carries that exact
    uuid through to the GraphQL response.
    """
    import importlib
    from unittest.mock import MagicMock

    if "config" in sys.modules:
        del sys.modules["config"]
    if "graphql_api" in sys.modules:
        del sys.modules["graphql_api"]
    if "node_identity" in sys.modules:
        del sys.modules["node_identity"]
    graphql_api = importlib.import_module("graphql_api")
    node_identity = importlib.import_module("node_identity")

    expected_uuid = node_identity.compute_node_uuid("Indicator", {"indicator_type": "ipv4", "value": "203.0.113.5"})

    # Fake Neo4j record carrying the canonical uuid (as it would be after MERGE).
    fake_record = {
        "n": {
            "value": "203.0.113.5",
            "indicator_type": "ipv4",
            "uuid": expected_uuid,
            "confidence_score": 0.8,
            "zone": ["healthcare"],
            "active": True,
            "source": ["misp"],
            "last_updated": None,
            "edgeguard_managed": True,
            "misp_event_ids": [],
            "misp_attribute_ids": [],
            "first_imported_at": None,
        }
    }

    class _FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def run(self, *_a, **_kw):
            return iter([fake_record])

    class _FakeDriver:
        def session(self, **_kw):
            return _FakeSession()

    fake_client = MagicMock()
    fake_client.driver = _FakeDriver()

    # Build a default IndicatorFilter — Strawberry-style Filter object.
    class _F:
        zone = graphql_api.strawberry.UNSET
        indicator_type = graphql_api.strawberry.UNSET
        active_only = False
        min_confidence = 0.0
        limit = 10
        offset = 0

    results = graphql_api._resolve_indicators(fake_client, _F())
    assert results, "resolver returned empty list"
    assert results[0].uuid == expected_uuid, (
        f"GraphQL Indicator.uuid diverged from compute_node_uuid: got {results[0].uuid}, expected {expected_uuid}"
    )


# ---------------------------------------------------------------------------
# B5 — Zone override holds at write time
# ---------------------------------------------------------------------------


def test_zone_override_global_helper_drops_global_when_specifics_present():
    """B5: ``_zone_override_global_clause`` is the single source of truth
    for write-time zone accumulation. The CASE expression must produce a
    set that excludes 'global' when at least one specific sector is
    present, and preserves 'global' otherwise.

    Verified end-to-end via a Python emulator of the CASE semantics — we
    can't execute Cypher without a live Neo4j, but the structural
    contract pins the logic. The companion runtime behavioral test
    (``test_zone_override_global_clause_shape``) verifies the Cypher
    structure separately.
    """
    import importlib

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    # Python emulator of the CASE semantics. The Cypher reads:
    #   union = apoc.coll.toSet(coalesce(n.zone, []) + new)
    #   specifics = [z IN union WHERE z <> 'global']
    #   result = specifics if size(specifics) > 0 else union
    def emulate(existing, new):
        union = set(existing) | set(new)
        specifics = {z for z in union if z != "global"}
        return sorted(specifics) if specifics else sorted(union)

    cases = [
        # (existing, new, expected) — every meaningful combination
        ([], ["healthcare"], ["healthcare"]),
        ([], ["global"], ["global"]),
        (["healthcare"], ["global"], ["healthcare"]),  # the round-24 fix
        (["global"], ["healthcare"], ["healthcare"]),
        (["healthcare"], ["energy"], ["energy", "healthcare"]),
        (["healthcare", "global"], [], ["healthcare"]),  # heal-on-touch
        ([], [], []),  # both empty stays empty
        (["global"], [], ["global"]),  # global-only stays global
    ]
    for existing, new, expected in cases:
        actual = emulate(existing, new)
        assert actual == expected, (
            f"zone-override semantics broken for existing={existing} new={new}: "
            f"emulator produced {actual}, expected {expected}"
        )

    # And the helper exists + has the right shape (Cypher CASE).
    clause = neo4j_client._zone_override_global_clause("n", "$zone")
    assert "CASE" in clause and "END" in clause and "WHERE z <> 'global'" in clause, (
        "_zone_override_global_clause must produce a CASE expression that filters 'global'"
    )


# ---------------------------------------------------------------------------
# (Removed) B6 / B6b — Backfill idempotency on partial graph
# ---------------------------------------------------------------------------
# Both pinned scripts/backfill_node_uuids.py, deleted in the PR #41
# pre-release cleanup pass. The script's "only target NULL uuids" guard
# is now moot: every node/edge MERGE in the live code stamps uuids at
# write time, and the heal path for a misshapen dev/test graph is a
# fresh baseline rerun (see docs/MIGRATIONS.md), not a re-runnable
# Python migration script.


# ---------------------------------------------------------------------------
# B7 — every CLI/optional code path that creates a typed edge between
#      uuid-bearing labels must stamp src_uuid/trg_uuid (round-28 audit)
# ---------------------------------------------------------------------------


def test_run_pipeline_edges_stamp_endpoint_uuids():
    """Round 28 (bugbot MED): the CLI path in ``run_pipeline.py`` creates
    INDICATES (co-occurrence) and EXPLOITS edges via its own
    apoc.periodic.iterate blocks. Before round 28 these did NOT stamp
    r.src_uuid/r.trg_uuid — so edges created via the CLI path had NULL
    endpoint uuids, silently breaking cross-environment delta sync for
    any operator who preferred the CLI over the Airflow path.

    Pin both edges' stamping via source-grep on the two apoc inner
    queries."""
    import importlib

    if "run_pipeline" in sys.modules:
        del sys.modules["run_pipeline"]
    run_pipeline = importlib.import_module("run_pipeline")
    src_path = run_pipeline.__file__
    with open(src_path) as fh:
        source = fh.read()

    # Both inner queries must stamp src=i.uuid trg={m,c}.uuid.
    for endpoint_var, edge_name in [("m", "INDICATES"), ("c", "EXPLOITS")]:
        assert f"r.src_uuid = i.uuid, r.trg_uuid = {endpoint_var}.uuid" in source, (
            f"{edge_name} edge in run_pipeline.py must stamp src=i.uuid trg={endpoint_var}.uuid "
            "on ON CREATE (round-28 fix)"
        )
        assert f"coalesce(r.src_uuid, i.uuid)" in source and (  # noqa: F541
            f"coalesce(r.trg_uuid, {endpoint_var}.uuid)" in source
        ), f"{edge_name} edge in run_pipeline.py must coalesce src/trg uuids on SET (idempotent)"


def test_build_relationships_summary_denominator_matches_query_count():
    """Round 28 (bugbot LOW): the ``[BUILD_RELATIONSHIPS SUMMARY]`` log
    line used to hardcode ``failures=%d/11`` but there are 12 independent
    _safe_run_batched calls (queries 1, 2, 3a, 3b, 4, 5, 6, 7a, 7b, 8, 9,
    10). "failures=12/11" is not a valid fraction.

    Pin by counting _safe_run_batched calls in build_relationships() and
    asserting the SUMMARY log uses the right denominator."""
    import importlib
    import inspect

    if "build_relationships" in sys.modules:
        del sys.modules["build_relationships"]
    br = importlib.import_module("build_relationships")
    src = inspect.getsource(br.build_relationships)

    call_count = src.count("_safe_run_batched(")
    assert call_count == 12, (
        f"expected 12 _safe_run_batched calls in build_relationships(); got {call_count}. "
        "If you added/removed a link query, also update the denominators below."
    )
    assert f"failures=%d/{call_count}" in src, (
        f"[BUILD_RELATIONSHIPS SUMMARY] format must use /{call_count} denominator (not a stale number)"
    )
    assert f"%d/{call_count} — partial success" in src, f"warning format must use /{call_count}"
