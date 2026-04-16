"""Regression tests for the 3 bugbot findings on PR #33.

These tests pin down the fixes so a future refactor can't silently undo them:

1. **HIGH** — 6 standalone create_*_relationship helpers had bogus
   ``row.src_uuid`` / ``row.trg_uuid`` references in their non-UNWIND
   Cypher. Every call would crash at runtime. Fix: use bound endpoint
   variables (``a.uuid``, ``m.uuid``, ``i.uuid``, ``v.uuid``, ``s.uuid``,
   ``t.uuid``) instead — same Mechanism B pattern that ``build_relationships.py``
   uses.
2. **MED** — Tool→Technique IMPLEMENTS_TECHNIQUE branch passed
   ``{"name": nm}`` to ``edge_endpoint_uuids("Tool", …)``, but Tool's
   natural key is ``mitre_id`` → wrong uuid via ``__missing__`` fallback.
   Plus ``q_tool_implements`` Cypher MATCHed by ``tool.name = row.entity``
   but the Tool from_key in parse_attribute is ``{"mitre_id": …}``, so
   every Tool row was silently dropped. Fix: split the dispatch into
   per-label branches with the right key, MATCH by ``tool.mitre_id``.
3. **MED** — ``_NATURAL_KEYS`` and ``_LABEL_NATURAL_KEY_FIELDS`` were
   parallel maps that had to stay manually synced. Adding a label to one
   without the other silently produced wrong uuids. Fix: derive
   ``_LABEL_NATURAL_KEY_FIELDS`` from ``_NATURAL_KEYS`` so they cannot
   diverge.
"""

from __future__ import annotations

import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# Finding #1 — broken row.* references in 6 standalone helpers
# ---------------------------------------------------------------------------


def test_standalone_helpers_use_bound_endpoint_vars_not_row():
    """The 6 single-row create_*_relationship functions are NOT UNWIND queries
    — referencing ``row.src_uuid`` / ``row.trg_uuid`` would crash with
    "Variable `row` not defined". They must use the MATCHed node's bound
    variable name (``a``, ``m``, ``i``, ``v``, ``s``, ``t``, ``tool``)."""
    import neo4j_client

    src_path = neo4j_client.__file__
    with open(src_path) as fh:
        source = fh.read()

    # Range covering the standalone helpers (between the merge_tool function
    # end and the start of create_misp_relationships_batch).
    helper_start = source.find("def create_actor_technique_relationship")
    helper_end = source.find("def create_misp_relationships_batch")
    assert helper_start > 0 and helper_end > helper_start, "helper region not found"
    helper_block = source[helper_start:helper_end]

    # The bug was these literal references — must NOT appear in the helper region.
    assert "row.src_uuid" not in helper_block, (
        "broken `row.src_uuid` reference in a non-UNWIND helper — would crash at runtime"
    )
    assert "row.trg_uuid" not in helper_block, (
        "broken `row.trg_uuid` reference in a non-UNWIND helper — would crash at runtime"
    )

    # Bound-variable form must be present (one of these per query).
    assert "coalesce(r.src_uuid, a.uuid)" in helper_block, "expected a.uuid endpoint stamp (actor_technique)"
    assert "coalesce(r.src_uuid, m.uuid)" in helper_block, (
        "expected m.uuid endpoint stamp (malware_actor / indicator_malware)"
    )
    assert "coalesce(r.src_uuid, i.uuid)" in helper_block, "expected i.uuid endpoint stamp (indicator_*)"
    assert "coalesce(r.src_uuid, v.uuid)" in helper_block, "expected v.uuid endpoint stamp (vulnerability_sector)"


def test_create_misp_relationships_batch_still_uses_row_vars_for_other_fields():
    """The batch UNWIND queries still use ``row.*`` for other fields
    (``row.source_id``, ``row.confidence``, ``row.misp_event_id``, etc.) —
    those are correct inside ``UNWIND $rows AS row``. Only the src_uuid /
    trg_uuid stamps switched to bound-var form (Mechanism B) in round 4.
    Catches a regression where someone over-zealously removes ALL ``row.*``
    references."""
    import neo4j_client

    with open(neo4j_client.__file__) as fh:
        source = fh.read()

    batch_start = source.find("def create_misp_relationships_batch")
    batch_end = source.find("def get_stats")
    assert batch_start > 0 and batch_end > batch_start
    batch_block = source[batch_start:batch_end]

    # These must remain — they're needed for the UNWIND row contract.
    assert "row.source_id" in batch_block, "row.source_id removed (regression)"
    assert "row.confidence" in batch_block, "row.confidence removed (regression)"
    assert "row.misp_event_id" in batch_block, "row.misp_event_id removed (regression)"


# ---------------------------------------------------------------------------
# Finding #2 — Tool key in IMPLEMENTS_TECHNIQUE branch
# ---------------------------------------------------------------------------


def test_tool_branch_uses_mitre_id_not_name():
    """Tool's natural key (UNIQUE constraint) is ``mitre_id``. The dispatch
    must read it from ``fk.get("mitre_id")``, not ``fk.get("name")``, and
    pass ``{"mitre_id": …}`` to edge_endpoint_uuids. Pre-fix: the
    Malware/Tool branch used ``fk.get("name")`` for both, silently dropping
    every Tool row (parse_attribute sends Tool from_key as {"mitre_id": …}).
    """
    import neo4j_client

    with open(neo4j_client.__file__) as fh:
        source = fh.read()

    batch_start = source.find("def create_misp_relationships_batch")
    batch_end = source.find("def get_stats")
    block = source[batch_start:batch_end]

    # Must have a Tool-specific branch using mitre_id.
    assert 'elif from_type == "Tool":' in block, "Tool branch must be split out from Malware"
    # Must read the mitre_id from from_key.
    assert 'fk.get("mitre_id")' in block, "Tool branch must read mitre_id from from_key"
    # The Tool row must put mitre_id into row.entity (q_tool_implements MATCHes
    # by tool.mitre_id = row.entity, not tool.name).
    assert '"entity_label": "Tool"' in block, "Tool branch must tag rows with entity_label='Tool'"


def test_q_tool_implements_matches_by_mitre_id():
    """Pre-fix the q_tool_implements MATCH was ``tool.name = row.entity``.
    Now Tool rows put mitre_id in ``row.entity``, so the MATCH must be by
    ``mitre_id``."""
    import neo4j_client

    with open(neo4j_client.__file__) as fh:
        source = fh.read()

    # Locate the q_tool_implements TEMPLATE ASSIGNMENT (not the comment
    # mentioning it earlier in the dispatch loop).
    idx = source.find('q_tool_implements = """')
    assert idx > 0, "q_tool_implements template assignment not found"
    # Look at the next ~800 chars (the query string)
    chunk = source[idx : idx + 800]

    assert "MATCH (tool:Tool {mitre_id: row.entity})" in chunk, (
        "q_tool_implements must MATCH by tool.mitre_id, not tool.name (Tool's natural key is mitre_id)"
    )
    # Negative: the legacy name-based MATCH must be gone.
    assert "tool.name = row.entity" not in chunk, "legacy tool.name MATCH must be removed"


# ---------------------------------------------------------------------------
# Finding #3 — duplicate parallel natural-key maps
# ---------------------------------------------------------------------------


def test_label_field_map_is_derived_from_natural_keys():
    """The two maps used to require manual sync. They must now share a single
    source of truth — adding a label to ``_NATURAL_KEYS`` automatically
    populates ``_LABEL_NATURAL_KEY_FIELDS`` (lowercase view)."""
    from node_identity import _LABEL_NATURAL_KEY_FIELDS, _NATURAL_KEYS

    # Cardinality: every label in _NATURAL_KEYS appears in the lowercase map.
    assert len(_NATURAL_KEYS) == len(_LABEL_NATURAL_KEY_FIELDS), (
        "the two maps must have the same number of entries (one is derived from the other)"
    )

    # Per-label fields: they MUST be the same tuple under the lowercase key.
    for label, fields in _NATURAL_KEYS.items():
        lc = label.lower()
        assert lc in _LABEL_NATURAL_KEY_FIELDS, (
            f"label {label!r} in _NATURAL_KEYS but not in derived _LABEL_NATURAL_KEY_FIELDS — derivation broken"
        )
        assert _LABEL_NATURAL_KEY_FIELDS[lc] == fields, (
            f"field tuple drift for {label!r}: _NATURAL_KEYS={fields} "
            f"_LABEL_NATURAL_KEY_FIELDS[{lc!r}]={_LABEL_NATURAL_KEY_FIELDS[lc]}"
        )


def test_adding_a_label_to_natural_keys_propagates_to_lowercase_map():
    """Live derivation check — even if _NATURAL_KEYS is patched at runtime
    (e.g. monkeypatched in a test), the lowercase view should track. This
    pins down the contract that the two maps are not independently
    maintained.
    """
    # We can't actually mutate the module dict mid-test cleanly without leaking
    # state — instead, assert on the source code that the lowercase map is
    # built via dict comprehension from _NATURAL_KEYS, not as an independent
    # literal. This is a structural check that catches the bugbot-flagged
    # maintenance hazard.
    import node_identity

    with open(node_identity.__file__) as fh:
        source = fh.read()

    assert "label.lower(): fields for label, fields in _NATURAL_KEYS.items()" in source, (
        "_LABEL_NATURAL_KEY_FIELDS must be derived from _NATURAL_KEYS via dict "
        "comprehension — anything else risks the two maps drifting silently"
    )


def test_uuid_unchanged_after_consolidation():
    """The map consolidation MUST NOT change any uuid — same canonical input,
    same uuid out. Frozen anchor values for the threat-intel core."""
    from node_identity import compute_node_uuid

    # These uuids are pinned values from the test_node_identity.py parity
    # tests. If consolidation changed canonicalization, these would fail.
    assert (
        compute_node_uuid("Indicator", {"indicator_type": "ipv4", "value": "203.0.113.5"})
        == "6ca3af4a-4bf1-57c9-846d-ec8f80861fd0"
    )
    assert compute_node_uuid("Malware", {"name": "Emotet"}) == "774960af-0687-56b1-9c05-ae55cd62ed58"
    assert compute_node_uuid("Vulnerability", {"cve_id": "CVE-2024-1234"}) == "85b67b2e-bb0c-5a7a-ae6f-2b6cc1aa077b"


# ---------------------------------------------------------------------------
# Bugbot 2nd-round finding #4 — CVE GraphQL resolver missing uuid pass-through
# ---------------------------------------------------------------------------


def test_cve_graphql_resolver_passes_uuid_through():
    """Every other node-type resolver in graphql_api.py was updated to
    ``uuid=n.get("uuid")`` when the GraphQL schema gained the field. The CVE
    resolver was the one miss — bugbot caught it on PR #33 round 2. Without
    this pass-through, GraphQL CVE queries always returned ``uuid: null``
    even when the underlying Neo4j CVE node had a populated uuid."""
    import graphql_api

    with open(graphql_api.__file__) as fh:
        source = fh.read()

    # Locate the CVE(...) constructor (near line 151 historically).
    idx = source.find("return CVE(")
    assert idx > 0, "CVE constructor not found in graphql_api"
    # Look at the next ~1500 chars (the constructor's keyword args).
    chunk = source[idx : idx + 1500]
    assert "uuid=c.get(" in chunk, "CVE resolver must pass uuid=c.get('uuid') — bugbot finding on PR #33 round 2"


# ---------------------------------------------------------------------------
# Bugbot 2nd-round finding #5 — case-insensitive label lookup
# ---------------------------------------------------------------------------


def test_lowercase_label_input_returns_correct_stix_type():
    """For labels whose STIX type DIFFERS from the lowercased Neo4j label
    (ThreatActor → intrusion-set, Technique → attack-pattern, CVE/Vulnerability →
    vulnerability, Sector → identity, Tactic → x-mitre-tactic), passing the
    label in lowercase MUST produce the same uuid as passing it proper-cased.

    Pre-fix the case-tolerance fallback had a guard
    ``obj_type != label.strip()`` that was False when the input was already
    lowercase — the reverse-lookup loop was skipped and the lowercased Neo4j
    label was used as the STIX type, producing a wrong uuid."""
    from node_identity import compute_node_uuid

    # ThreatActor → intrusion-set
    proper = compute_node_uuid("ThreatActor", {"name": "APT28"})
    lower = compute_node_uuid("threatactor", {"name": "APT28"})
    assert proper == lower, "ThreatActor lowercase input must yield the same uuid"

    # Technique → attack-pattern
    assert compute_node_uuid("Technique", {"mitre_id": "T1059"}) == compute_node_uuid(
        "technique", {"mitre_id": "T1059"}
    )

    # CVE → vulnerability
    assert compute_node_uuid("CVE", {"cve_id": "CVE-2024-1234"}) == compute_node_uuid(
        "cve", {"cve_id": "CVE-2024-1234"}
    )

    # Sector → identity
    assert compute_node_uuid("Sector", {"name": "healthcare"}) == compute_node_uuid("sector", {"name": "healthcare"})

    # Tactic → x-mitre-tactic
    assert compute_node_uuid("Tactic", {"mitre_id": "TA0001"}) == compute_node_uuid("tactic", {"mitre_id": "TA0001"})


# ---------------------------------------------------------------------------
# Bugbot 3rd-round finding #6 — adjacent string literals inside triple-quoted
# string break Cypher syntax in apoc.periodic.iterate
# ---------------------------------------------------------------------------


def test_bridge_vulnerability_cve_inner_action_is_single_string_literal():
    """Bugbot caught a HIGH-severity bug: the bridge_vulnerability_cve query
    used multiple adjacent ``'...' '...'`` Cypher string fragments INSIDE a
    triple-quoted Python string. Python doesn't implicit-concat adjacent
    quoted strings inside ``\"\"\"...\"\"\"`` — the fragments were sent to
    Neo4j as separate tokens, producing a Cypher syntax error.

    Structural check: read the source and verify the inner apoc.periodic.iterate
    action does NOT have the ``' '` adjacent-quote pattern (which is the
    fingerprint of the broken form)."""
    import enrichment_jobs

    with open(enrichment_jobs.__file__) as fh:
        source = fh.read()

    # Find the bridge_vulnerability_cve function block.
    start = source.find("def bridge_vulnerability_cve")
    end = source.find("\ndef ", start + 1)
    assert start > 0 and end > start, "bridge_vulnerability_cve not found"
    block = source[start:end]

    # Look for the inner apoc.periodic.iterate action argument. The broken
    # form had a closing single-quote followed by whitespace/newline followed
    # by an opening single-quote — the adjacent-literal smell. This pattern
    # appears inside the broken form (`'...REFERS_TO]->(c) ' '  SET ...`)
    # but NOT in the fixed single-line form.
    #
    # Catch the specific anti-pattern: closing-quote, then whitespace/newline,
    # then opening-quote, all WITHIN the inner Cypher action argument.
    import re

    # Restrict to the inner second argument of apoc.periodic.iterate.
    iterate_idx = block.find("apoc.periodic.iterate(")
    assert iterate_idx > 0
    after = block[iterate_idx : iterate_idx + 1500]

    # Adjacent-quote anti-pattern: `' \n   '` or `'   \n  '` (closing then opening).
    bad_pattern = re.search(r"'\s*\n\s+'", after)
    assert bad_pattern is None, (
        "bridge_vulnerability_cve inner action has adjacent quoted string "
        "fragments inside a triple-quoted outer string — Python won't "
        "concat them and Cypher will reject the result. Keep the inner "
        "action as a single long line."
    )


# ---------------------------------------------------------------------------
# Bugbot 4th-round finding #7 (MED) — refactor batch templates to bound-var uuids
# ---------------------------------------------------------------------------


def test_create_misp_relationships_batch_uses_bound_var_uuids_not_row():
    """Pre-fix the batch templates SET ``r.src_uuid = coalesce(..., row.src_uuid)``
    where ``row.src_uuid`` was Python-precomputed in the dispatch loop. Bugbot
    flagged that this could disagree with the actual node's ``n.uuid`` if the
    producer's from_key was incomplete (e.g. Indicator missing ``indicator_type``
    → uuid computed from `""` → `__missing__` fallback that doesn't match the
    node).

    Fix: every Cypher template now reads its MATCHed node's bound-variable
    ``.uuid`` directly (Mechanism B). Same pattern build_relationships.py uses
    — eliminates the precomputation/MATCH mismatch class entirely.

    This test asserts the structural change."""
    import neo4j_client

    with open(neo4j_client.__file__) as fh:
        source = fh.read()

    batch_start = source.find("def create_misp_relationships_batch")
    batch_end = source.find("\n    def get_stats")
    assert batch_start > 0 and batch_end > batch_start
    block = source[batch_start:batch_end]

    # Negative: no Cypher template should use ``row.src_uuid`` / ``row.trg_uuid``
    # any more — all are now bound-var uuids.
    assert "row.src_uuid" not in block, (
        "create_misp_relationships_batch must not reference row.src_uuid — use bound-var .uuid instead (Mechanism B)"
    )
    assert "row.trg_uuid" not in block, (
        "create_misp_relationships_batch must not reference row.trg_uuid — use bound-var .uuid instead (Mechanism B)"
    )

    # Positive: each of the 11 templates uses bound-var .uuid for src/trg.
    # Spot-check a few representative ones.
    assert "coalesce(r.src_uuid, a.uuid)" in block, "actor_employs / attr templates"
    assert "coalesce(r.src_uuid, m.uuid)" in block, "malware_implements / attr / ind_mal templates"
    assert "coalesce(r.src_uuid, i.uuid)" in block, "ind_mal / tgt_ind / expl templates"
    assert "coalesce(r.trg_uuid, t.uuid)" in block, "*_employs / *_implements / use_technique templates"
    assert "coalesce(r.trg_uuid, s.uuid)" in block, "tgt_ind / tgt_vuln / tgt_cve templates"


def test_dispatch_loop_no_longer_precomputes_endpoint_uuids():
    """The dispatch loop in create_misp_relationships_batch should no longer
    call ``edge_endpoint_uuids(...)`` — that's what enabled the precomputation/
    MATCH mismatch bug. The Sector node uuid IS still pre-computed (separate
    field, used for the auto-CREATEd Sector node, NOT for the edge endpoint
    uuid which the template reads off ``s.uuid`` directly)."""
    import inspect

    import neo4j_client

    src = inspect.getsource(neo4j_client.Neo4jClient.create_misp_relationships_batch)
    assert "edge_endpoint_uuids(" not in src, (
        "create_misp_relationships_batch must not pre-compute endpoint uuids — "
        "templates use bound-var .uuid (Mechanism B). The function still imports "
        "edge_endpoint_uuids for OTHER call sites; this test only checks the batch."
    )
    # But the Sector uuid stamping is still in (used for the Sector node's own uuid).
    assert 'compute_node_uuid("Sector"' in src, (
        "Sector node uuid pre-computation should stay — used for the auto-CREATEd "
        "Sector node, which has no upstream MERGE pass to stamp its uuid."
    )


# ---------------------------------------------------------------------------
# Bugbot 4th-round finding #8 (LOW) — falsy numeric values in natural keys
# ---------------------------------------------------------------------------


def test_falsy_numeric_natural_key_values_are_preserved():
    """Pre-fix: ``str(key_dict.get(f, "") or "")`` collapsed any falsy value
    (0, False, 0.0) to the empty string. NetworkService(port=0) produced the
    same canonical string as missing port, generating a uuid collision.

    Fix: explicit None-check via _fmt() so legitimate 0 / False / 0.0 values
    survive."""
    from node_identity import compute_node_uuid

    u_port_0 = compute_node_uuid("NetworkService", {"port": 0, "protocol": "tcp"})
    u_port_80 = compute_node_uuid("NetworkService", {"port": 80, "protocol": "tcp"})
    u_port_missing = compute_node_uuid("NetworkService", {"protocol": "tcp"})

    assert u_port_0 != u_port_missing, (
        "port=0 (legitimate value) must NOT collide with missing-port — bugbot finding on PR #33 round 4"
    )
    assert u_port_0 != u_port_80, "different ports must yield different uuids"

    # Also test False (just to pin down the contract for boolean fields, even
    # though no current label uses one — defensive against future labels).
    # We exercise the generic-fallback branch of _natural_key_string.
    from node_identity import canonical_node_key

    canon_false = canonical_node_key("UnknownLabel", {"flag": False})
    canon_missing = canonical_node_key("UnknownLabel", {})
    assert canon_false != canon_missing, "False must NOT collide with missing-key"


# ---------------------------------------------------------------------------
# Bugbot 4th-round finding #9 (LOW) — Sector uuid in build_relationships.py
# ---------------------------------------------------------------------------


def test_build_relationships_stamps_sector_uuid():
    """The 7a (TARGETS) and 7b (AFFECTS) queries in build_relationships.py
    auto-CREATE Sector nodes. Pre-fix they didn't stamp ``sec.uuid``, leaving
    the auto-created Sector node with NULL uuid and the connected edge's
    ``r.trg_uuid = coalesce(..., sec.uuid)`` inheriting NULL.

    Fix: pre-compute the 4 known sector uuids in Python, embed as a Cypher
    CASE expression in the inner query so ``sec.uuid`` is set on creation."""
    import build_relationships

    # _SECTOR_UUIDS map exists with the 4 documented sectors.
    assert hasattr(build_relationships, "_SECTOR_UUIDS"), "_SECTOR_UUIDS map must exist at module level"
    assert set(build_relationships._SECTOR_UUIDS.keys()) == {
        "healthcare",
        "energy",
        "finance",
        "global",
    }, "Sector pre-compute map must cover the 4 documented zones"

    # Each uuid matches what compute_node_uuid produces for Sector(name=...).
    from node_identity import compute_node_uuid

    for zone, expected_uuid in build_relationships._SECTOR_UUIDS.items():
        assert expected_uuid == compute_node_uuid("Sector", {"name": zone}), (
            f"Pre-computed Sector uuid for {zone!r} must match compute_node_uuid"
        )

    # _SECTOR_UUID_CASE is a non-empty Cypher CASE expression.
    case_expr = build_relationships._SECTOR_UUID_CASE
    assert case_expr.startswith("CASE zone_name "), "must be a CASE on zone_name"
    assert case_expr.endswith(" END"), "must terminate with END"
    for zone in ("healthcare", "energy", "finance", "global"):
        assert f"WHEN '{zone}' THEN" in case_expr, f"zone {zone!r} missing from CASE"

    # The 7a and 7b queries reference the CASE expression. In the source, the
    # CASE is interpolated via f-string (`f"  ON CREATE SET sec.uuid = {_SECTOR_UUID_CASE} "`),
    # so we can't look for the literal CASE string — instead, assert the
    # f-string interpolation pattern appears at least twice (one per 7a / 7b).
    with open(build_relationships.__file__) as fh:
        source = fh.read()
    interp_count = source.count("ON CREATE SET sec.uuid = {_SECTOR_UUID_CASE}")
    assert interp_count >= 2, (
        f"both 7a (TARGETS) and 7b (AFFECTS) must stamp sec.uuid via the CASE "
        f"interpolation — found {interp_count} occurrences, expected ≥2"
    )


def test_lowercase_label_uuid_matches_pinned_anchor():
    """Strongest form of the case-tolerance assertion: lowercase input must
    produce the SAME canonical uuid that the rest of the system uses. If
    this drifts, a delta-sync push from a producer that lowercased its labels
    would fail to MERGE on the cloud (different uuids)."""
    from node_identity import compute_node_uuid

    # APT28 anchor — the pinned uuid is the ONE canonical value the system
    # uses for ThreatActor(name="APT28") regardless of label case.
    expected = compute_node_uuid("ThreatActor", {"name": "APT28"})
    assert compute_node_uuid("threatactor", {"name": "APT28"}) == expected
    assert compute_node_uuid(" THREATACTOR ", {"name": "APT28"}) == expected
    assert compute_node_uuid("ThreatActor", {"name": "APT28"}) == expected
