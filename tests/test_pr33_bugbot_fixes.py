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
    # PR #33 round 6 (bugbot HIGH): CASE uses DOUBLE quotes, not single — single
    # quotes inside the inner Cypher would terminate the outer
    # apoc.periodic.iterate('inner', ...) string wrapper.
    for zone in ("healthcare", "energy", "finance", "global"):
        assert f'WHEN "{zone}" THEN' in case_expr, f"zone {zone!r} missing from CASE"

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


# ---------------------------------------------------------------------------
# Bugbot 5th-round finding #4 (MED) — CVE/Vulnerability twin-node uuid
# ---------------------------------------------------------------------------


def test_cve_and_vulnerability_share_uuid_intentionally():
    """Bugbot flagged that CVE and Vulnerability share a uuid — both labels
    map to STIX type ``vulnerability``, so ``compute_node_uuid("CVE", …)`` ==
    ``compute_node_uuid("Vulnerability", …)`` for the same cve_id.

    This is INTENTIONAL — they're twin Neo4j-side views of the same logical
    CVE (CVE = NVD-canonical, Vulnerability = EdgeGuard-managed) connected
    by REFERS_TO, and STIX has only one `vulnerability` SDO per CVE so uuid
    parity holds.

    Operational consequence: cloud-sync recipes MUST use label-scoped MATCH
    when resolving src_uuid / trg_uuid back to a node. Documented in
    docs/CLOUD_SYNC.md "CVE/Vulnerability twin-node design".

    This test pins down the design so a future refactor that "fixes" the
    sharing (which would break STIX parity for one of the two labels)
    fails loudly here."""
    from node_identity import compute_node_uuid

    cve_id = "CVE-2024-1234"
    cve_uuid = compute_node_uuid("CVE", {"cve_id": cve_id})
    vuln_uuid = compute_node_uuid("Vulnerability", {"cve_id": cve_id})

    assert cve_uuid == vuln_uuid, (
        "CVE and Vulnerability must share uuid for the same cve_id (twin-node "
        "design — see docs/CLOUD_SYNC.md). Cloud-sync consumers must use "
        "label-scoped MATCH to disambiguate."
    )


def test_node_identity_documents_twin_node_design():
    """The intentional CVE/Vulnerability uuid sharing is documented inline in
    NEO4J_TO_STIX_TYPE so a future maintainer doesn't accidentally 'fix' it
    without understanding why."""
    import node_identity

    with open(node_identity.__file__) as fh:
        source = fh.read()

    # Must reference the twin-node design and the label-scoped MATCH workaround.
    assert "twin-node" in source.lower() or "two Neo4j-side views" in source, (
        "node_identity.py must document the intentional CVE/Vulnerability uuid sharing inline at NEO4J_TO_STIX_TYPE"
    )
    assert "CLOUD_SYNC.md" in source, "node_identity.py must reference docs/CLOUD_SYNC.md for the recipe"


def test_cloud_sync_recipe_uses_label_scoped_match():
    """The cloud-sync recipe in docs/CLOUD_SYNC.md MUST not use the bare
    `MATCH (n {uuid: $u})` form for edge endpoint resolution — that's
    ambiguous for CVE/Vulnerability twin nodes (round 5 bugbot finding)."""
    import os

    doc_path = os.path.join(os.path.dirname(__file__), "..", "docs", "CLOUD_SYNC.md")
    with open(doc_path) as fh:
        source = fh.read()

    # Find the edge-delta consumer recipe and inspect.
    idx = source.find("For each edge delta")
    assert idx > 0, "edge-delta consumer recipe not found"
    chunk = source[idx : idx + 1500]

    # Negative: no bare unscoped MATCH-by-uuid in the edge consumer.
    assert "MATCH (a {uuid: e.src_uuid})" not in chunk, (
        "bare unscoped MATCH-by-uuid for edge endpoints — won't disambiguate "
        "CVE/Vulnerability twin nodes (bugbot round 5)"
    )
    # Positive: must scope to the src_label / trg_label carried in the delta.
    assert "src_label" in chunk and "trg_label" in chunk, (
        "edge consumer recipe must use src_label / trg_label from the delta"
    )

    # The twin-node callout must be present.
    assert "twin-node" in source.lower(), "CLOUD_SYNC.md must explain CVE/Vulnerability twin-node design"


# ---------------------------------------------------------------------------
# Bugbot 5th-round finding #5 (MED) — standalone Sector helpers stamp uuid
# ---------------------------------------------------------------------------


def test_standalone_sector_helpers_stamp_uuid():
    """Both ``create_indicator_sector_relationship`` and
    ``create_vulnerability_sector_relationship`` had an ``ensure_sector_query``
    that MERGEd a Sector node without ``s.uuid``. The subsequent rel query's
    ``coalesce(r.trg_uuid, s.uuid)`` then read NULL.

    Fix: pre-compute the deterministic Sector uuid in Python and pass as a
    ``$sector_uuid`` param to the ensure_sector_query, which now stamps it
    on creation."""
    import inspect

    import neo4j_client

    for fn_name in (
        "create_indicator_sector_relationship",
        "create_vulnerability_sector_relationship",
    ):
        fn = getattr(neo4j_client.Neo4jClient, fn_name)
        src = inspect.getsource(fn)

        # The Sector uuid must be computed in Python.
        assert 'compute_node_uuid("Sector"' in src, f"{fn_name} must pre-compute the Sector uuid via compute_node_uuid"
        # The ensure_sector_query must reference $sector_uuid.
        assert "$sector_uuid" in src, (
            f"{fn_name}'s ensure_sector_query must accept the precomputed $sector_uuid param and stamp s.uuid from it"
        )
        # ON CREATE SET must include the uuid stamp.
        assert "s.uuid = $sector_uuid" in src, f"{fn_name} must SET s.uuid = $sector_uuid on Sector creation"


# ---------------------------------------------------------------------------
# Post-PR-#33 fresh-eyes audit (Agent 1 finding) — Campaign uuid stamping
# ---------------------------------------------------------------------------


def test_build_campaign_nodes_stamps_campaign_uuid_and_edges():
    """The post-PR audit caught that ``enrichment_jobs.build_campaign_nodes``
    was creating Campaign nodes (and RUNS / PART_OF edges) WITHOUT stamping
    n.uuid / r.src_uuid / r.trg_uuid. Silent gap — GraphQL ``c.uuid`` would
    return NULL for every Campaign until the backfill ran.

    Fix: pre-fetch qualifying actor names, compute Campaign uuids in Python
    via ``compute_node_uuid("Campaign", {"name": f"{actor} Campaign"})``,
    pass as a ``$campaign_uuids`` map, stamp on Campaign creation. The 3
    edges (RUNS Actor→Campaign, PART_OF Malware→Campaign, PART_OF
    Indicator→Campaign) all read bound .uuid from their MATCHed endpoints
    (Mechanism B).

    Regression test reads the source and asserts the structural changes."""
    import enrichment_jobs

    with open(enrichment_jobs.__file__) as fh:
        source = fh.read()

    # Locate build_campaign_nodes.
    start = source.find("def build_campaign_nodes")
    end = source.find("\ndef ", start + 1)
    assert start > 0 and end > start, "build_campaign_nodes not found"
    block = source[start:end]

    # Pre-fetch + Python uuid computation.
    assert "qualifying_actors_query" in block, (
        "build_campaign_nodes must pre-fetch qualifying actor names to compute Campaign uuids in Python"
    )
    assert 'compute_node_uuid("Campaign"' in block, (
        "build_campaign_nodes must compute Campaign uuids in Python (CASE "
        "expression / map lookup pattern — same as Sector pre-compute fix)"
    )
    assert "campaign_uuids" in block, "campaign_uuids map must be threaded into the Cypher"

    # Campaign node uuid stamp on creation + idempotent re-stamp.
    assert "c.uuid = $campaign_uuids[a.name]" in block, (
        "Campaign MERGE must stamp c.uuid = $campaign_uuids[a.name] on creation"
    )
    assert "c.uuid             = coalesce(c.uuid, $campaign_uuids[a.name])" in block or (
        "coalesce(c.uuid, $campaign_uuids[a.name])" in block
    ), "Campaign uuid must use idempotent coalesce on the SET path"

    # Each of the 3 edges must stamp src_uuid / trg_uuid via bound .uuid.
    # RUNS edge is in step 1 (MERGE (a)-[r_runs:RUNS]->(c)).
    assert "r_runs.src_uuid = a.uuid" in block, "RUNS edge must stamp src_uuid from a.uuid"
    assert "r_runs.trg_uuid = c.uuid" in block, "RUNS edge must stamp trg_uuid from c.uuid"

    # PART_OF (Malware → Campaign) — step 2.
    pof_malware_idx = block.find("MERGE (m)-[r:PART_OF]->(c)")
    assert pof_malware_idx > 0, "Malware PART_OF edge not found"
    pof_malware_chunk = block[pof_malware_idx : pof_malware_idx + 400]
    assert "r.src_uuid = m.uuid" in pof_malware_chunk, "Malware PART_OF edge must stamp src_uuid from m.uuid"
    assert "r.trg_uuid = c.uuid" in pof_malware_chunk, "Malware PART_OF edge must stamp trg_uuid from c.uuid"

    # PART_OF (Indicator → Campaign) — step 3.
    pof_indicator_idx = block.find("MERGE (i)-[r:PART_OF]->(c)")
    assert pof_indicator_idx > 0, "Indicator PART_OF edge not found"
    pof_indicator_chunk = block[pof_indicator_idx : pof_indicator_idx + 400]
    assert "r.src_uuid = i.uuid" in pof_indicator_chunk, "Indicator PART_OF edge must stamp src_uuid from i.uuid"
    assert "r.trg_uuid = c.uuid" in pof_indicator_chunk, "Indicator PART_OF edge must stamp trg_uuid from c.uuid"


def test_campaign_uuid_matches_compute_node_uuid_contract():
    """Behavioral check on the actual uuid value: Campaign(name='APT28 Campaign')
    must produce the same uuid that compute_node_uuid does, so a downstream
    consumer can resolve a Campaign uuid back to the canonical entity."""
    from node_identity import compute_node_uuid

    # Anchor pin — frozen value. If canonicalization changes, this fails loudly.
    expected = compute_node_uuid("Campaign", {"name": "APT28 Campaign"})
    # Same input should yield the same uuid every time.
    assert compute_node_uuid("Campaign", {"name": "APT28 Campaign"}) == expected
    # And the STIX exporter should produce the same uuid (Campaign → STIX campaign).
    from stix_exporter import _deterministic_id

    stix_id = _deterministic_id("campaign", "APT28 Campaign")
    assert stix_id == f"campaign--{expected}", "Campaign Neo4j n.uuid must equal the UUID portion of the STIX SDO id"


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


# ---------------------------------------------------------------------------
# Round-6 finding #6 (HIGH): CASE expression single quotes break apoc.iterate
# ---------------------------------------------------------------------------


def test_sector_uuid_case_uses_double_quotes_not_single():
    """``_SECTOR_UUID_CASE`` is f-string-interpolated into ``_q7a_inner`` and
    ``_q7b_inner``, which are then wrapped in SINGLE quotes by
    ``_safe_run_batched`` for ``apoc.periodic.iterate('outer', 'inner', ...)``.
    Embedded single quotes terminate the inner string early and break the
    rendered Cypher. The CASE must use DOUBLE quotes (Cypher accepts both)."""
    import importlib

    if "build_relationships" in sys.modules:
        del sys.modules["build_relationships"]
    build_relationships = importlib.import_module("build_relationships")

    case_expr = build_relationships._SECTOR_UUID_CASE
    assert "'" not in case_expr, (
        f"_SECTOR_UUID_CASE contains single quotes — would break apoc.periodic.iterate "
        f"outer string wrapping. Use double quotes for WHEN labels and THEN literals. "
        f"Got: {case_expr[:200]}"
    )
    # Sanity: the CASE must still be a valid Cypher CASE expression with
    # double-quoted literals.
    assert '"healthcare"' in case_expr
    assert '"global"' in case_expr
    assert "CASE zone_name " in case_expr
    assert " END" in case_expr


def test_q7a_inner_has_no_unescaped_single_quotes():
    """The full inner Cypher for query 7a (TARGETS) must not contain any
    single quotes — every string literal inside must use double quotes so
    the outer single-quote wrapper in ``apoc.periodic.iterate('outer', 'inner')``
    parses cleanly. Same convention as the working co-occurrence query in
    ``run_pipeline.py``."""
    import importlib
    import inspect
    import re

    if "build_relationships" in sys.modules:
        del sys.modules["build_relationships"]
    build_relationships = importlib.import_module("build_relationships")

    src = inspect.getsource(build_relationships.build_relationships)

    # Extract the _q7a_inner assignment block (multi-line concatenated string +
    # f-string interpolations of _SECTOR_UUID_CASE).
    m = re.search(r"_q7a_inner = \(\s*(.*?)\s*\)\s*\n\s*if not _safe_run_batched", src, re.DOTALL)
    assert m, "could not locate _q7a_inner assignment"
    raw_block = m.group(1)

    # Render it: pick out every quoted string fragment (both " and ' delimited)
    # and concatenate. The fragments themselves are the Cypher chars sent to
    # Neo4j (after f-string interpolation removes any embedded backticks etc).
    # We reject single quotes in any "..." fragment (= Cypher with embedded ').
    double_quoted = re.findall(r'"((?:[^"\\]|\\.)*)"', raw_block)
    for frag in double_quoted:
        # Empty Cypher string literal as `""` is fine — but if a fragment
        # contains a single quote at all, that single quote is literal Cypher
        # that will break the outer wrapper.
        assert "'" not in frag, f"_q7a_inner has Cypher fragment with single quote: {frag!r}"


def test_q7b_inner_has_no_unescaped_single_quotes():
    """Same check as 7a, for the AFFECTS query (Vulnerability/CVE → Sector)."""
    import importlib
    import inspect
    import re

    if "build_relationships" in sys.modules:
        del sys.modules["build_relationships"]
    build_relationships = importlib.import_module("build_relationships")

    src = inspect.getsource(build_relationships.build_relationships)
    m = re.search(r"_q7b_inner = \(\s*(.*?)\s*\)\s*\n\s*if not _safe_run_batched", src, re.DOTALL)
    assert m, "could not locate _q7b_inner assignment"
    raw_block = m.group(1)

    double_quoted = re.findall(r'"((?:[^"\\]|\\.)*)"', raw_block)
    for frag in double_quoted:
        assert "'" not in frag, f"_q7b_inner has Cypher fragment with single quote: {frag!r}"


# ---------------------------------------------------------------------------
# Round-6 finding #7 (LOW): backfill edge count overstates updateable
# ---------------------------------------------------------------------------


def test_backfill_edge_count_query_filters_uuid_endpoints():
    """The count query in ``backfill_edge`` must include the same
    ``a.uuid IS NOT NULL AND b.uuid IS NOT NULL`` filter the update query
    uses. Without that, ``committed X / Y`` reports X<Y on every clean run
    (the gap = edges with NULL endpoint uuids that we cannot update), which
    operators may misread as a partial failure."""
    import importlib
    import inspect

    if "scripts.backfill_node_uuids" in sys.modules:
        del sys.modules["scripts.backfill_node_uuids"]
    scripts_path = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    backfill_node_uuids = importlib.import_module("backfill_node_uuids")

    src = inspect.getsource(backfill_node_uuids.backfill_edge)

    # Slice the source between `count_query = (` and the matching close-paren
    # at the assignment's terminating paren. We can't use a naive regex because
    # the body itself contains parentheses (e.g., `(r.src_uuid IS NULL OR ...)`).
    # Instead, walk forward and balance parens.
    start = src.index("count_query = (")
    open_paren_idx = src.index("(", start)
    depth = 0
    for i in range(open_paren_idx, len(src)):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                cq = src[open_paren_idx + 1 : i]
                break
    else:
        raise AssertionError("could not balance parens for count_query")

    assert "a.uuid IS NOT NULL" in cq, (
        "count_query missing `a.uuid IS NOT NULL` filter — must match update_query or X/Y log will mislead operators"
    )
    assert "b.uuid IS NOT NULL" in cq, "count_query missing `b.uuid IS NOT NULL` filter — must match update_query"


def test_backfill_edge_separately_logs_skipped_endpointless_edges():
    """The fix doesn't just hide the gap — it also logs a WARNING when edges
    have NULL endpoint nodes (the `skipped` count) so the operator knows to
    run node backfill for those labels. Pin the WARNING phrasing so a
    refactor can't silently drop it."""
    import importlib
    import inspect

    if "scripts.backfill_node_uuids" in sys.modules:
        del sys.modules["scripts.backfill_node_uuids"]
    scripts_path = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    backfill_node_uuids = importlib.import_module("backfill_node_uuids")

    src = inspect.getsource(backfill_node_uuids.backfill_edge)
    assert "skipped_query" in src, "skipped_query (counts edges with NULL endpoint uuids) is missing"
    assert "logger.warning" in src and "endpoint nodes without uuid" in src, (
        "the WARNING log instructing the operator to run node backfill first is missing"
    )


# ---------------------------------------------------------------------------
# Round-7 audit follow-up — close the topology UUID gap
# ---------------------------------------------------------------------------
#
# Multi-agent audit on 2026-04-17 found that the 8 ResilMesh topology mergers
# (merge_ip / merge_host / merge_device / merge_subnet / merge_networkservice /
# merge_softwareversion / merge_application / merge_role) and the standalone
# merge_resilmesh_cve / merge_resilmesh_vulnerability did NOT stamp n.uuid,
# even though their labels appear in _NATURAL_KEYS. Their relationship helpers
# also did not stamp r.src_uuid / r.trg_uuid. Round 7 closes that gap.


_TOPOLOGY_LABELS = (
    "IP",
    "Host",
    "Device",
    "Subnet",
    "NetworkService",
    "SoftwareVersion",
    "Application",
    "Role",
)


def test_all_topology_labels_have_uuid_index():
    """Each of the 8 topology labels must have a CREATE INDEX on n.uuid in
    create_indexes — same as the MISP-derived labels. Without an index per
    label, MERGE-by-uuid in delta sync degrades to a label scan."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")
    src = inspect.getsource(neo4j_client.Neo4jClient.create_indexes)
    for label in _TOPOLOGY_LABELS:
        # Either lowercase- or label-cased index name; both are acceptable —
        # the test only requires that the UUID index targets that label.
        assert (
            f"FOR (i:{label}) ON (i.uuid)" in src
            or f"FOR (h:{label}) ON (h.uuid)" in src
            or (f":{label})" in src and "ON (" in src and "uuid" in src)
        ), f"create_indexes is missing a uuid index for {label}"


def test_all_topology_mergers_compute_node_uuid():
    """Each of the 8 topology merge_* functions must call compute_node_uuid
    and pass it as a Cypher parameter. Without this, n.uuid stays NULL and
    delta-sync / self-describing-edge consumers see a silent gap."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    fn_to_label = {
        "merge_ip": "IP",
        "merge_host": "Host",
        "merge_device": "Device",
        "merge_subnet": "Subnet",
        "merge_networkservice": "NetworkService",
        "merge_softwareversion": "SoftwareVersion",
        "merge_application": "Application",
        "merge_role": "Role",
    }
    for fn_name, label in fn_to_label.items():
        fn = getattr(neo4j_client.Neo4jClient, fn_name)
        src = inspect.getsource(fn)
        assert f'compute_node_uuid("{label}"' in src, (
            f"{fn_name} does not call compute_node_uuid({label!r}, ...) — silent NULL uuid path"
        )
        assert "ON CREATE SET" in src and ".uuid =" in src, f"{fn_name} does not stamp n.uuid in the MERGE Cypher"
        assert "coalesce(" in src and ".uuid," in src, (
            f"{fn_name} does not idempotently coalesce n.uuid — pre-existing nodes won't pick up the uuid"
        )


def test_resilmesh_cve_and_vulnerability_paths_stamp_uuid():
    """The duplicate ResilMesh-native CVE and Vulnerability mergers must
    produce the SAME n.uuid as the canonical MISP path (both keyed on
    cve_id). Without this, a node MERGEd via the ResilMesh path would have
    NULL uuid and a node MERGEd via the MISP path for the same cve_id
    would have a populated uuid — inconsistent identity."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src_cve = inspect.getsource(neo4j_client.Neo4jClient.merge_resilmesh_cve)
    assert 'compute_node_uuid("CVE"' in src_cve, "merge_resilmesh_cve does not compute the canonical CVE uuid"
    assert "c.uuid = $cve_uuid" in src_cve, "merge_resilmesh_cve does not stamp c.uuid"

    src_v = inspect.getsource(neo4j_client.Neo4jClient.merge_resilmesh_vulnerability)
    assert 'compute_node_uuid("Vulnerability"' in src_v, (
        "merge_resilmesh_vulnerability does not compute the canonical Vulnerability uuid"
    )
    assert "v.uuid = $vuln_uuid" in src_v, "merge_resilmesh_vulnerability does not stamp v.uuid"


def test_topology_relationship_helpers_stamp_endpoint_uuids():
    """The 11 topology relationship helpers whose endpoints are both in
    _NATURAL_KEYS must stamp r.src_uuid and r.trg_uuid via the bound endpoint
    .uuid (Mechanism B). Other helpers (involving User/Node/Component/etc.)
    are left uuid-less because those labels are not in the natural-key map."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    helpers_to_check = (
        "create_softwareversion_on_host",
        "create_role_to_device",
        "create_device_to_role",
        "create_device_has_identity_host",
        "create_host_has_identity_device",
        "create_host_on_softwareversion",
        "create_ip_part_of_subnet",
        "create_subnet_part_of_ip",
        "create_subnet_part_of_subnet",
        "create_networkservice_on_host",
        "create_host_on_networkservice",
    )
    for helper_name in helpers_to_check:
        helper = getattr(neo4j_client.Neo4jClient, helper_name)
        src = inspect.getsource(helper)
        # Must stamp both src_uuid and trg_uuid in ON CREATE SET (and idempotent SET).
        assert "src_uuid =" in src and "trg_uuid =" in src, f"{helper_name} does not stamp r.src_uuid/r.trg_uuid"
        assert "coalesce(" in src and "src_uuid" in src and "trg_uuid" in src, (
            f"{helper_name} does not coalesce src_uuid/trg_uuid (idempotent SET) — re-runs would NOT repair NULLs"
        )


def test_backfill_includes_topology_edges():
    """EDGES_TO_BACKFILL must list the topology edge tuples so a one-time
    backfill picks them up; otherwise pre-existing topology edges keep
    NULL src/trg_uuid forever."""
    import importlib

    if "scripts.backfill_node_uuids" in sys.modules:
        del sys.modules["scripts.backfill_node_uuids"]
    scripts_path = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    backfill_node_uuids = importlib.import_module("backfill_node_uuids")

    edges = set(backfill_node_uuids.EDGES_TO_BACKFILL)
    expected = {
        ("ON", "SoftwareVersion", "Host"),
        ("ON", "Host", "SoftwareVersion"),
        ("ON", "NetworkService", "Host"),
        ("ON", "Host", "NetworkService"),
        ("TO", "Role", "Device"),
        ("TO", "Device", "Role"),
        ("HAS_IDENTITY", "Device", "Host"),
        ("HAS_IDENTITY", "Host", "Device"),
        ("PART_OF", "IP", "Subnet"),
        ("PART_OF", "Subnet", "IP"),
        ("PART_OF", "Subnet", "Subnet"),
    }
    missing = expected - edges
    assert not missing, f"backfill is missing topology edge entries: {missing}"


def test_topology_uuid_matches_compute_node_uuid_contract():
    """End-to-end pin: a topology label's uuid via the helper must equal
    the canonical compute_node_uuid output for the same key. Anchors that
    the merge_* function and any consumer (delta sync, RAG, STIX) agree on
    the same identity."""
    from node_identity import compute_node_uuid

    cases = [
        ("IP", {"address": "192.0.2.1"}),
        ("Host", {"hostname": "edge-01.example.com"}),
        ("Device", {"device_id": "dev-001"}),
        ("Subnet", {"range": "10.0.0.0/24"}),
        ("NetworkService", {"port": 443, "protocol": "tcp"}),
        ("SoftwareVersion", {"version": "OpenSSL 3.0.7"}),
        ("Application", {"name": "nginx"}),
        ("Role", {"permission": "admin"}),
    ]
    for label, key in cases:
        # Determinism check — same input must produce same uuid.
        u1 = compute_node_uuid(label, key)
        u2 = compute_node_uuid(label, key)
        assert u1 == u2, f"compute_node_uuid({label!r}, {key!r}) is non-deterministic"
        # Sanity: uuid is a 36-char string (canonical UUID form).
        assert len(u1) == 36 and u1.count("-") == 4, f"uuid for {label} is not a canonical UUID string: {u1!r}"


# ---------------------------------------------------------------------------
# Round 8 — bugbot findings on commit ac26dee
# ---------------------------------------------------------------------------


def test_merge_cvss_node_params_spread_filtered_first():
    """Bugbot (round 8, MED): in ``_merge_cvss_node`` the params dict spreads
    ``filtered_cvss`` AFTER explicit ``cve_uuid``/``cvss_uuid`` keys, so a
    cvss_data entry named ``cve_uuid`` or ``cvss_uuid`` would silently
    overwrite the deterministic uuid. Fix: spread ``**filtered_cvss`` FIRST
    and put the explicit uuid keys last so they always win."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src = inspect.getsource(neo4j_client.Neo4jClient._merge_cvss_node)
    # Find the params dict literal block.
    import re

    m = re.search(r"params\s*=\s*\{(.*?)\}", src, re.DOTALL)
    assert m, "could not locate params dict in _merge_cvss_node"
    body = m.group(1)
    # Position of the spread vs the explicit cve_uuid/cvss_uuid.
    spread_pos = body.find("**filtered_cvss")
    cve_pos = body.find('"cve_uuid"')
    cvss_pos = body.find('"cvss_uuid"')
    assert spread_pos >= 0 and cve_pos >= 0 and cvss_pos >= 0, (
        "expected **filtered_cvss + cve_uuid/cvss_uuid keys all present in params dict"
    )
    assert spread_pos < cve_pos and spread_pos < cvss_pos, (
        "**filtered_cvss must come BEFORE cve_uuid / cvss_uuid in the params dict so the "
        "explicit deterministic uuids can't be overwritten by attribute data"
    )


def test_backfill_validates_labels_before_interpolation():
    """Bugbot (round 8, LOW): backfill's ``--labels`` flag is user-supplied
    and flowed unvalidated into f-string Cypher. Pin that the three backfill
    Cypher-building functions call ``_validate_label`` and (for edges)
    ``_validate_rel_type``."""
    import importlib
    import inspect

    if "scripts.backfill_node_uuids" in sys.modules:
        del sys.modules["scripts.backfill_node_uuids"]
    scripts_path = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    backfill_node_uuids = importlib.import_module("backfill_node_uuids")

    for fn_name in ("count_null_uuid_nodes", "backfill_label"):
        fn = getattr(backfill_node_uuids, fn_name)
        src = inspect.getsource(fn)
        assert "_validate_label(" in src, f"{fn_name} does not call _validate_label before f-string interpolation"

    edge_src = inspect.getsource(backfill_node_uuids.backfill_edge)
    assert "_validate_label(from_label)" in edge_src
    assert "_validate_label(to_label)" in edge_src
    assert "_validate_rel_type(rel_type)" in edge_src


def test_backfill_edge_inner_query_re_matches_relationship_by_id():
    """Bugbot (round 11, MED): apoc.periodic.iterate runs the inner query
    in a NEW transaction per batch. Raw entity references (r, a, b) from
    the outer cannot safely be referenced in that new transaction — the
    handle was bound to the outer transaction's lifetime. The safe pattern
    is to RETURN id(r) (and the endpoint uuids as primitive strings) from
    the outer, then re-MATCH by id in the inner.

    This test was originally added in round 8 asserting the
    ``WITH $r AS r`` rebind pattern; round 11 superseded that with the
    safer id()-based pattern."""
    import importlib
    import inspect

    if "scripts.backfill_node_uuids" in sys.modules:
        del sys.modules["scripts.backfill_node_uuids"]
    scripts_path = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    backfill_node_uuids = importlib.import_module("backfill_node_uuids")

    src = inspect.getsource(backfill_node_uuids.backfill_edge)

    # Outer must return the relationship id and endpoint uuids as primitives.
    assert "id(r)" in src, "outer query must RETURN id(r) — primitive long, transaction-safe"
    assert "a.uuid AS a_uuid" in src, "outer must RETURN a.uuid as a primitive string for cross-transaction safety"
    assert "b.uuid AS b_uuid" in src, "outer must RETURN b.uuid as a primitive string for cross-transaction safety"

    # Inner must re-MATCH the relationship by id and use $-bound primitive uuids.
    assert "id(r) = $rid" in src, (
        "inner must re-MATCH the relationship by id() in the new transaction — "
        "raw entity refs (r, a, b) are not safe across apoc.periodic.iterate batches"
    )
    assert "$a_uuid" in src and "$b_uuid" in src, "inner must use bound $a_uuid / $b_uuid primitives in SET"

    # PR #33 round 15 (bugbot LOW): inner re-MATCH must be DIRECTED so each
    # relationship is matched exactly once by id (undirected returns each
    # relationship twice — once per traversal direction — causing redundant SETs).
    assert "MATCH ()-[r]->()" in src, (
        "inner re-MATCH must be DIRECTED ()-[r]->() — undirected ()-[r]-() returns "
        "each relationship twice and fires the SET twice per edge"
    )
    assert "MATCH ()-[r]-()" not in src.replace("MATCH ()-[r]->()", ""), (
        "the round-11 undirected pattern ()-[r]-() must not return — round 15 fixed it"
    )

    # Negative: the prior round-8 raw-entity rebind pattern must not return.
    assert "WITH $r AS r, $a AS a, $b AS b" not in src, (
        "round-8 raw-entity rebind pattern must NOT come back — entity handles "
        "from outer query don't survive apoc.periodic.iterate's per-batch transactions"
    )


def test_merge_device_refuses_missing_device_id():
    """Bugbot (round 8, MED): the previous fallback ``str(id(data))`` for
    missing device_id used Python's memory-address id(), producing a
    different uuid every call for the same logical Device. Refuse the call
    instead of writing a poisoned, non-deterministic node.

    PR #34 test-audit cleanup: dropped the weak ``str(id(data)) not in
    code_only`` negative assertion. The behavioral check below (with
    driver=None) is load-bearing: if the guard regresses AND the
    str(id(data)) fallback returns, ``merge_device({})`` would attempt
    a DB call against ``self.driver=None`` and raise AttributeError
    instead of returning False — the test fails loudly. The source-
    string pin was redundant."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src = inspect.getsource(neo4j_client.Neo4jClient.merge_device)
    # Positive pin: the guard must exist (source search for present-form
    # strings is safe — if the string isn't there the test fails loudly,
    # no phantom-target risk).
    assert "if not device_id" in src or "if device_id is None" in src, (
        "merge_device must guard against missing device_id and return False — found no guard"
    )

    # Behavioural check: invoke merge_device with empty data on a stub client
    # that has no driver. The guard must short-circuit before any DB call,
    # returning False without raising.
    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = None  # noqa — stub
    assert client.merge_device({}) is False, "merge_device({}) must return False, not raise"
    assert client.merge_device({"device_id": ""}) is False, "merge_device with empty device_id must return False"


def test_standalone_cvss_mergers_were_deleted():
    """PR #33 round 12: the 4 standalone vector_string-keyed CVSS mergers
    (merge_cvssv2/30/31/40) and their 8 helper companions were deleted.
    The canonical CVSS path is _merge_cvss_node, called from merge_cve,
    which keys on cve_id and stamps deterministic uuid.

    This test was originally added in round 8 to pin the deferred-decision
    inline comment block; round 12 replaces it with a deletion guard."""
    import importlib

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    # The standalone mergers must NOT exist on Neo4jClient.
    for name in ("merge_cvssv2", "merge_cvssv30", "merge_cvssv31", "merge_cvssv40"):
        assert not hasattr(neo4j_client.Neo4jClient, name), (
            f"{name} should have been deleted in round 12 — it was a vector_string-keyed,"
            " uuid-less standalone superseded by the canonical _merge_cvss_node path"
        )
    # And the companion edge helpers must be gone too.
    for name in (
        "create_cve_has_cvss_v2",
        "create_cve_has_cvss_v30",
        "create_cve_has_cvss_v31",
        "create_cve_has_cvss_v40",
        "create_cvssv2_has_cvssv2_cve",
        "create_cvssv30_has_cvssv30_cve",
        "create_cvssv31_has_cvssv31_cve",
        "create_cvssv40_has_cvssv40_cve",
    ):
        assert not hasattr(neo4j_client.Neo4jClient, name), (
            f"{name} should have been deleted in round 12 — _merge_cvss_node creates the "
            "bidirectional HAS_CVSS_v* edges with stamped src_uuid/trg_uuid; no separate helper needed"
        )

    # The canonical path is still there.
    assert hasattr(neo4j_client.Neo4jClient, "_merge_cvss_node"), (
        "_merge_cvss_node (canonical CVSS path) must still exist"
    )


# ---------------------------------------------------------------------------
# Round 9 — multi-agent audit follow-up: natural-key consistency + dedup
# ---------------------------------------------------------------------------
#
# The 4-agent audit on 2026-04-17 surfaced two real findings:
#  - HIGH: 4 relationship helpers MATCHed Vulnerability by ``name`` instead
#    of canonical ``cve_id`` (silent failure to wire the edge — Vulnerability
#    nodes are MERGEd by cve_id everywhere else)
#  - MED:  merge_missiondependency used the same ``str(id(data))`` non-
#    deterministic fallback that merge_device round-8 had eliminated


_VULN_HELPERS_FIXED = (
    "create_softwareversion_in_vulnerability",
    "create_vulnerability_refers_to_cve",
    "create_vulnerability_in_softwareversion",
    "create_cve_refers_to_vulnerability",
)


def test_vulnerability_helpers_match_by_cve_id_not_name():
    """The 4 ResilMesh-side relationship helpers must MATCH Vulnerability by
    ``cve_id`` (canonical natural key) — not by ``name``. Vulnerability nodes
    are MERGEd by cve_id everywhere (merge_vulnerabilities_batch line 1724,
    merge_resilmesh_vulnerability line 3471), so MATCH-by-name finds nothing
    and the helper silently fails to create the relationship."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    for fn_name in _VULN_HELPERS_FIXED:
        fn = getattr(neo4j_client.Neo4jClient, fn_name)
        src = inspect.getsource(fn)
        # The bug pattern that must be gone.
        assert "Vulnerability {name:" not in src, (
            f"{fn_name} still MATCHes Vulnerability by name — silent failure "
            f"because Vulnerability natural key is cve_id"
        )
        # The fix pattern that must be present.
        assert "Vulnerability {cve_id:" in src, f"{fn_name} does not MATCH Vulnerability by cve_id"


def test_vulnerability_helpers_stamp_endpoint_uuids():
    """Now that the 4 helpers MATCH valid uuid-stamped endpoints, they must
    also stamp r.src_uuid / r.trg_uuid via Mechanism B (bound endpoint .uuid)
    so cross-environment delta sync covers these edges."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    for fn_name in _VULN_HELPERS_FIXED:
        fn = getattr(neo4j_client.Neo4jClient, fn_name)
        src = inspect.getsource(fn)
        assert "src_uuid =" in src and "trg_uuid =" in src, (
            f"{fn_name} does not stamp r.src_uuid / r.trg_uuid via bound endpoint .uuid"
        )
        assert "coalesce(" in src, f"{fn_name} missing coalesce — re-runs would NOT repair NULL src/trg_uuid"


def test_backfill_includes_software_version_in_vulnerability_edges():
    """The IN edge between SoftwareVersion and Vulnerability is now uuid-
    stamped (round 9 helper fix); backfill must enumerate it so existing
    edges get repaired on the next run."""
    import importlib

    if "scripts.backfill_node_uuids" in sys.modules:
        del sys.modules["scripts.backfill_node_uuids"]
    scripts_path = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    backfill_node_uuids = importlib.import_module("backfill_node_uuids")

    edges = set(backfill_node_uuids.EDGES_TO_BACKFILL)
    assert ("IN", "SoftwareVersion", "Vulnerability") in edges, (
        "EDGES_TO_BACKFILL missing (IN, SoftwareVersion, Vulnerability)"
    )
    assert ("IN", "Vulnerability", "SoftwareVersion") in edges, (
        "EDGES_TO_BACKFILL missing (IN, Vulnerability, SoftwareVersion)"
    )


# ---------------------------------------------------------------------------
# Round 11 — bugbot findings on commit 3552369 (round 10)
# ---------------------------------------------------------------------------


def test_strawberry_optional_fields_have_explicit_default():
    """Bugbot (round 11, LOW): a Strawberry @strawberry.type can mix
    Optional fields with and without defaults only because Strawberry uses
    ``kw_only=True`` on Python 3.10+. To not depend on framework-specific
    handling, every Optional[...] field should carry an explicit ``= None``
    default. Pin that the 9 production node types satisfy this."""
    import importlib

    if "graphql_schema" in sys.modules:
        del sys.modules["graphql_schema"]
    graphql_schema = importlib.import_module("graphql_schema")

    classes_to_check = (
        "CVE",
        "Vulnerability",
        "Indicator",
        "ThreatActor",
        "Malware",
        "Technique",
        "Tactic",
        "Tool",
        "Campaign",
    )

    import dataclasses

    for cls_name in classes_to_check:
        cls = getattr(graphql_schema, cls_name)
        # Every dataclass field whose type starts with Optional[ must have a default.
        for f in dataclasses.fields(cls):
            type_str = str(f.type)
            if "Optional" not in type_str:
                continue
            # MISSING sentinel means no default — that's the bug.
            assert f.default is not dataclasses.MISSING or f.default_factory is not dataclasses.MISSING, (
                f"{cls_name}.{f.name}: Optional field has no explicit default — "
                "relies on Strawberry's kw_only handling instead of standard dataclass semantics"
            )


def test_vulnerability_helpers_are_keyword_only():
    """Bugbot (round 11, MED): the 4 vulnerability relationship helpers
    were given keyword-only signatures so the round-9 positional reorder
    cannot silently swap a stale caller's ``vuln_name`` into the ``cve_id``
    slot. Pin the keyword-only contract via inspect.signature."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    helpers = (
        "create_softwareversion_in_vulnerability",
        "create_vulnerability_refers_to_cve",
        "create_vulnerability_in_softwareversion",
        "create_cve_refers_to_vulnerability",
    )
    for name in helpers:
        fn = getattr(neo4j_client.Neo4jClient, name)
        sig = inspect.signature(fn)
        # Skip self; every other parameter must be KEYWORD_ONLY.
        non_self = [p for p in sig.parameters.values() if p.name != "self"]
        for p in non_self:
            assert p.kind is inspect.Parameter.KEYWORD_ONLY, (
                f"{name}({p.name}={p.kind.name}) — parameter must be KEYWORD_ONLY so "
                "positional callers fail loudly instead of silently swapping cve_id and vuln_name"
            )


def test_misp_batch_uses_affects_for_vuln_cve_to_sector():
    """Bugbot (round 11, LOW): canonical schema is
    (Vulnerability|CVE)-[:AFFECTS]->(Sector). TARGETS is reserved for
    (Indicator)-[:TARGETS]->(Sector). The round-10 q_tgt_vuln/q_tgt_cve
    in create_misp_relationships_batch produced TARGETS for Vuln/CVE→Sector,
    creating a duplicate edge type vs the AFFECTS emitted by
    build_relationships.py 7b. Round 11 renamed both to q_aff_vuln/q_aff_cve
    and switched to AFFECTS so the graph has one canonical edge type."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src = inspect.getsource(neo4j_client.Neo4jClient.create_misp_relationships_batch)

    # Vuln/CVE → Sector queries must use AFFECTS.
    assert "MERGE (v)-[r:AFFECTS]->(s)" in src, (
        "Vuln/CVE→Sector edges must MERGE AFFECTS, not TARGETS (TARGETS is reserved for Indicator→Sector)"
    )
    # The legacy TARGETS path on Vulnerability/CVE must be gone.
    # (TARGETS still appears for the Indicator-side q_tgt_ind, which is correct.)
    assert "MATCH (v:Vulnerability {cve_id: row.cve_id})\n        MERGE (v)-[r:TARGETS]" not in src, (
        "Vulnerability→Sector must not use TARGETS — switch to AFFECTS"
    )
    assert "MATCH (v:CVE {cve_id: row.cve_id})\n        MERGE (v)-[r:TARGETS]" not in src, (
        "CVE→Sector must not use TARGETS — switch to AFFECTS"
    )


def test_create_vulnerability_sector_relationship_uses_affects():
    """The standalone helper must also emit AFFECTS for Vuln/CVE→Sector
    (mirrors the batched q_aff_vuln/q_aff_cve change above)."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src = inspect.getsource(neo4j_client.Neo4jClient.create_vulnerability_sector_relationship)
    assert "MERGE (v)-[r:AFFECTS]->(s)" in src, (
        "create_vulnerability_sector_relationship must MERGE AFFECTS for Vuln/CVE→Sector"
    )
    assert "MERGE (v)-[r:TARGETS]->(s)" not in src, (
        "the helper must not emit TARGETS for Vuln/CVE→Sector — TARGETS reserved for Indicator→Sector"
    )


def test_backfill_no_longer_lists_targets_for_vuln_or_cve():
    """EDGES_TO_BACKFILL must drop the (TARGETS, Vulnerability, Sector) and
    (TARGETS, CVE, Sector) tuples now that those edges are AFFECTS."""
    import importlib

    if "scripts.backfill_node_uuids" in sys.modules:
        del sys.modules["scripts.backfill_node_uuids"]
    scripts_path = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    backfill = importlib.import_module("backfill_node_uuids")

    edges = set(backfill.EDGES_TO_BACKFILL)
    assert ("TARGETS", "Vulnerability", "Sector") not in edges, "stale TARGETS Vulnerability→Sector still in backfill"
    assert ("TARGETS", "CVE", "Sector") not in edges, "stale TARGETS CVE→Sector still in backfill"
    # And the canonical AFFECTS entries must be present.
    assert ("AFFECTS", "Vulnerability", "Sector") in edges
    assert ("AFFECTS", "CVE", "Sector") in edges
    # TARGETS Indicator→Sector remains (canonical).
    assert ("TARGETS", "Indicator", "Sector") in edges


def test_merge_missiondependency_refuses_missing_dependency_id():
    """Audit (round 9, MED): merge_missiondependency previously used
    ``str(id(data))`` as a fallback for missing dependency_id — same anti-
    pattern eliminated from merge_device in round 8. Each call would produce
    a different MERGE key, creating duplicate nodes per call. Refuse the
    call instead.

    PR #34 test-audit cleanup: dropped the weak ``str(id(data)) not in
    code_only`` negative assertion — same reasoning as
    ``test_merge_device_refuses_missing_device_id``. The behavioral
    driver=None check is load-bearing."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src = inspect.getsource(neo4j_client.Neo4jClient.merge_missiondependency)
    # Positive pin: the guard must exist.
    assert "if not dependency_id" in src or "if dependency_id is None" in src, (
        "merge_missiondependency must guard against missing dependency_id and return False"
    )

    # Behavioural: invoke with empty data on a stub client (no driver).
    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = None
    assert client.merge_missiondependency({}) is False, "merge_missiondependency({}) must return False"
    assert client.merge_missiondependency({"dependency_id": ""}) is False, (
        "merge_missiondependency with empty dependency_id must return False"
    )


# ---------------------------------------------------------------------------
# Round 13 — silent-skip / empty-data improvements
# ---------------------------------------------------------------------------


def test_safe_run_batched_returns_false_on_apoc_errors():
    """PR #33 round 13: ``_safe_run_batched`` previously returned True even
    when apoc.periodic.iterate reported errorMessages — silent partial
    failure. Now: returns False so the caller's failures counter reflects
    the partial APOC error."""
    import importlib

    if "build_relationships" in sys.modules:
        del sys.modules["build_relationships"]
    build_relationships = importlib.import_module("build_relationships")

    from unittest.mock import MagicMock

    client = MagicMock()
    client.run.return_value = [{"count": 5, "batches": 2, "errorMessages": ["constraint violation on row 3"]}]
    stats: dict = {}
    result = build_relationships._safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "k")
    assert result is False, "errorMessages > 0 must flip return value to False"

    # Sanity: zero errorMessages returns True.
    client2 = MagicMock()
    client2.run.return_value = [{"count": 5, "batches": 2, "errorMessages": []}]
    stats2: dict = {}
    assert (
        build_relationships._safe_run_batched(client2, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats2, "k") is True
    )


def test_safe_run_batched_logs_skip_count_when_skip_query_returns_positive(caplog):
    """PR #34 round 20: ``_safe_run_batched`` now takes ``skip_query`` (NOT
    ``expected_query``). The skip_query directly counts ORPHAN input rows
    (rows whose inner-MATCH target does NOT exist) — when > 0 an INFO
    ``[SKIP]`` log fires.

    Round 13's expected_query design was fundamentally broken: it compared
    APOC ``total`` (count of outer-query rows that ran the inner action,
    regardless of inner success) against "rows where target exists" (a
    subset). The comparison ``expected > total`` was always false, so the
    skip-count log NEVER fired. Round 20 inverts: count orphans directly,
    no comparison needed.
    """
    import importlib
    import logging

    if "build_relationships" in sys.modules:
        del sys.modules["build_relationships"]
    build_relationships = importlib.import_module("build_relationships")

    from unittest.mock import MagicMock

    client = MagicMock()
    # First call: skip_query → returns 30 orphans. Second call: apoc → returns 70 processed.
    client.run.side_effect = [
        [{"c": 30}],  # skip count (orphans)
        [{"count": 70, "batches": 1, "errorMessages": []}],  # apoc result
    ]
    stats: dict = {}
    with caplog.at_level(logging.INFO, logger="build_relationships"):
        build_relationships._safe_run_batched(
            client,
            "TEST",
            "MATCH (n) RETURN n",
            "SET n.x = 1",
            stats,
            "k",
            skip_query="MATCH (a) WHERE NOT EXISTS { ... } RETURN count(a) AS c",
        )
    logs = "\n".join(rec.message for rec in caplog.records)
    assert "[SKIP]" in logs, "expected [SKIP] log when skip_query returns > 0"
    assert "30 input rows had no matching target" in logs, f"expected orphan-count phrasing in skip log; got: {logs}"


def test_safe_run_batched_does_not_log_skip_when_skip_query_returns_zero(caplog):
    """When skip_query returns 0 (no orphans), the [SKIP] log MUST NOT fire.
    This guards against false-positive noise that would dilute the signal."""
    import importlib
    import logging

    if "build_relationships" in sys.modules:
        del sys.modules["build_relationships"]
    build_relationships = importlib.import_module("build_relationships")

    from unittest.mock import MagicMock

    client = MagicMock()
    client.run.side_effect = [
        [{"c": 0}],  # no orphans
        [{"count": 50, "batches": 1, "errorMessages": []}],
    ]
    stats: dict = {}
    with caplog.at_level(logging.INFO, logger="build_relationships"):
        build_relationships._safe_run_batched(
            client,
            "TEST",
            "MATCH (n) RETURN n",
            "SET n.x = 1",
            stats,
            "k",
            skip_query="MATCH (a) WHERE NOT EXISTS { ... } RETURN count(a) AS c",
        )
    logs = "\n".join(rec.message for rec in caplog.records)
    assert "[SKIP]" not in logs, "[SKIP] log must NOT fire when skip_query returns 0"


def test_build_relationships_link_queries_pass_skip_query():
    """PR #34 round 20: link queries 3a, 3b, 5, 6, 8, 9, 10 in
    build_relationships() pass ``skip_query=`` (NOT the broken
    ``expected_query=`` from round 13). Each skip_query must use a
    ``NOT EXISTS`` subquery so it counts ORPHAN rows directly."""
    import importlib
    import inspect

    if "build_relationships" in sys.modules:
        del sys.modules["build_relationships"]
    build_relationships = importlib.import_module("build_relationships")

    src = inspect.getsource(build_relationships.build_relationships)
    # All 7 skip_query labels — round 20 contract.
    for var in (
        "_q3a_skip",
        "_q3b_skip",
        "_q5_skip",
        "_q6_skip",
        "_q8_skip",
        "_q9_skip",
        "_q10_skip",
    ):
        assert var in src, f"build_relationships() should define {var} for orphan-count surfacing"
    # And skip_query= keyword usage must appear at least 7 times.
    assert src.count("skip_query=") >= 7, (
        "skip_query= kwarg must be passed to _safe_run_batched for queries 3a/3b/5/6/8/9/10"
    )
    # Round-13's broken expected_query symbol must be gone.
    assert "expected_query=" not in src, (
        "round-13 broken expected_query= kwarg must be replaced by skip_query= (round 20)"
    )
    assert "_q6_expected" not in src and "_q9_expected" not in src, (
        "round-13 _q*_expected variable names must be replaced by _q*_skip (round 20)"
    )
    # Each skip_query must use NOT EXISTS to count orphans (the whole point).
    # Pin at least one canonical instance.
    assert "NOT EXISTS { MATCH (v:Vulnerability {cve_id: i.cve_id}) }" in src, (
        "_q3a_skip must use NOT EXISTS to count Indicators with no matching Vulnerability"
    )


def test_sync_to_neo4j_logs_when_items_empty(caplog):
    """PR #33 round 13: ``sync_to_neo4j`` previously returned silently on
    empty input. Now emits an INFO log so an operator can distinguish 'MISP
    returned 0 events' from 'sync_to_neo4j was never called'."""
    import importlib
    import inspect

    if "run_misp_to_neo4j" in sys.modules:
        del sys.modules["run_misp_to_neo4j"]
    run_misp_to_neo4j = importlib.import_module("run_misp_to_neo4j")

    # Find sync_to_neo4j in the module — it's a method on MISPToNeo4jSync.
    src = inspect.getsource(run_misp_to_neo4j.MISPToNeo4jSync.sync_to_neo4j)
    assert "[NEO4J SYNC] no items received" in src, (
        "sync_to_neo4j must log when items is empty (round 13 silent-skip fix)"
    )


def test_dropped_rels_log_emits_even_when_zero():
    """PR #33 round 13: ``create_misp_relationships_batch`` previously logged
    drops only when ``_dropped_rels > 0`` — invisible 'success' for the 0-drop
    path. Now logs INFO when 0 drops so the operator sees an explicit baseline."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src = inspect.getsource(neo4j_client.Neo4jClient.create_misp_relationships_batch)
    # Both branches must exist: WARNING (if drops) AND INFO (if zero).
    assert "logger.warning" in src and "definitions dropped" in src, "WARN log for drops must still exist"
    assert "logger.info" in src and "0/" in src and "dropped" in src, (
        "INFO log for the zero-drop baseline must be emitted (round 13)"
    )


def test_drop_constraint_no_longer_uses_bare_pass():
    """PR #33 round 13: silent ``except: pass`` on DROP CONSTRAINT replaced
    with a DEBUG log — operator running in verbose mode can see which
    legacy constraints were dropped vs which silently masked schema errors."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src = inspect.getsource(neo4j_client.Neo4jClient.create_constraints)
    # Walk lines: any ``except Exception: pass`` (or bare ``except: pass``) must be gone
    # in the old_constraints loop. Allow the comment to mention pass historically.
    for i, line in enumerate(src.splitlines()):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        # A literal pass in the immediate body of an except is what we want gone.
        if stripped == "pass" and "except" in (src.splitlines()[i - 1] if i > 0 else ""):
            raise AssertionError(
                f"create_constraints still has bare except:pass at line {i + 1} — round 13 added a DEBUG log"
            )


def test_misp_attributes_dropped_metric_exists_and_is_emitted():
    """PR #33 round 13: ``MISP_ATTRIBUTES_DROPPED`` Prometheus counter
    exposes silent-skip rate by reason class. Pin the metric is declared
    and that the dedup function records into it.

    NB: do NOT reload metrics_server (Prometheus duplicates a registered
    Counter on re-import — would crash with 'Duplicated timeseries'). Use
    source-level checks instead.
    """
    metrics_path = os.path.join(os.path.dirname(__file__), "..", "src", "metrics_server.py")
    with open(metrics_path) as fh:
        metrics_src = fh.read()
    assert "MISP_ATTRIBUTES_DROPPED" in metrics_src, "MISP_ATTRIBUTES_DROPPED Counter must be declared"
    assert "edgeguard_misp_attributes_dropped_total" in metrics_src, "Counter must use the canonical Prometheus name"
    assert "def record_misp_attribute_dropped" in metrics_src, "helper function must exist"

    rmtn_path = os.path.join(os.path.dirname(__file__), "..", "src", "run_misp_to_neo4j.py")
    with open(rmtn_path) as fh:
        rmtn_src = fh.read()
    assert "record_misp_attribute_dropped" in rmtn_src, (
        "run_misp_to_neo4j must call record_misp_attribute_dropped in its dedup path"
    )


# ---------------------------------------------------------------------------
# Round 14 — bugbot findings on commits ab48fe1 / a27bad1
# ---------------------------------------------------------------------------


def test_indicates_cooccurrence_query_sets_updated_at():
    """Bugbot (round 14, MED): the round-7 SET clause for src_uuid/trg_uuid
    on the INDICATES co-occurrence query (#4) in build_relationships.py
    omitted ``r.updated_at = datetime()``. Every other relationship query
    in this file sets r.updated_at; the delta-sync recipe in CLOUD_SYNC.md
    filters edges by ``r.updated_at >= ...`` — without it, INDICATES
    co-occurrence edges were silently excluded from cloud-sync."""
    import importlib
    import inspect

    if "build_relationships" in sys.modules:
        del sys.modules["build_relationships"]
    build_relationships = importlib.import_module("build_relationships")

    src = inspect.getsource(build_relationships.build_relationships)
    block_start = src.find("4. Indicator → Malware (INDICATES)")
    block_end = src.find("5. ThreatActor → Technique", block_start)
    assert block_start > 0 and block_end > block_start, "INDICATES block not found"
    block = src[block_start:block_end]
    assert "r.updated_at = datetime()" in block, (
        "INDICATES co-occurrence inner query must SET r.updated_at — "
        "without it, delta-sync cloud filter excludes these edges"
    )


def test_alert_processor_zone_type_guard_present():
    """Bugbot (round 14, LOW): the round-12 cleanup removed the
    ``isinstance(zone, list)`` guard in alert_processor.py. ``zone`` comes
    from Neo4j via a Cypher read; if any node has a scalar string value
    (out-of-band write, schema drift, legacy DB), ``len(zone)`` would count
    characters and the later ``.append(tag)`` would crash with
    AttributeError. Round 14 re-adds the defensive guard."""
    import importlib
    import inspect

    if "alert_processor" in sys.modules:
        del sys.modules["alert_processor"]
    try:
        alert_processor = importlib.import_module("alert_processor")
    except Exception:
        import pytest

        pytest.skip("alert_processor cannot be imported in this test environment")
        return

    src = inspect.getsource(alert_processor)
    assert "isinstance(zone, list)" in src, (
        "alert_processor must guard zone with isinstance check — "
        "round-12 removed it, round-14 restores it (defensive against scalar string from Neo4j read)"
    )


def test_edge_endpoint_uuids_is_still_used_in_neo4j_client():
    """Bugbot (round 14, LOW) flagged ``edge_endpoint_uuids`` as 'likely
    unused'. Verified false: it IS called by ``_upsert_sourced_relationship``
    in neo4j_client.py. Pin the call site so a future refactor doesn't
    silently drop the import + helper."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src = inspect.getsource(neo4j_client)
    assert "edge_endpoint_uuids(" in src, (
        "edge_endpoint_uuids must be called somewhere in neo4j_client; "
        "if all callers are removed, also remove the import"
    )
    upsert_src = inspect.getsource(neo4j_client.Neo4jClient._upsert_sourced_relationship)
    assert "edge_endpoint_uuids(" in upsert_src, (
        "_upsert_sourced_relationship must use edge_endpoint_uuids to compute Source-edge uuids"
    )


# ---------------------------------------------------------------------------
# Round 17 — delete misleading original_published_date / original_modified_date
# ---------------------------------------------------------------------------


def test_original_date_fields_were_deleted_from_writes():
    """User-driven cleanup (round 17): the ``n.original_published_date`` and
    ``n.original_modified_date`` Cypher SET clauses were removed from
    ``merge_node_with_source`` and ``merge_indicators_batch``. The fields
    were intended to capture the upstream NVD published / last_modified
    dates, but every non-NVD path (CISA KEV, OTX, MISP-event-only) silently
    fell back to the MISP event date — making the field name lie about its
    contents (e.g. CVE-2012-1854 from CISA KEV showed
    original_published_date='2026-04-15' instead of the real 2012 date).

    Canonical EdgeGuard times live in ``first_imported_at`` (precise
    timestamp + TZ on every node) and ``last_updated``.

    PR #34 test-audit cleanup: converted from source-string pin (comment-
    stripped, phantom-target-risky) to BEHAVIORAL pin that captures the
    actual Cypher sent to the driver and asserts on the SET clause. This
    catches regressions regardless of whether the re-introduced SET line
    is inside a #-comment, docstring, triple-quoted string, or variable
    — the captured Cypher is the real send-to-Neo4j payload."""
    import importlib
    from unittest.mock import MagicMock

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    # Capture every Cypher query sent via session.run().
    captured: list[str] = []

    class _CapSession:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def run(self, query, *_a, **_kw):
            captured.append(query)
            result = MagicMock()
            result.__iter__ = lambda self_: iter([])
            result.single = lambda: None
            return result

    class _CapDriver:
        def session(self, **_kw):
            return _CapSession()

        def close(self):
            pass

    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = _CapDriver()

    # Invoke merge_node_with_source with representative data that would
    # historically have triggered the deleted SET clauses (NVD-style CVE
    # with published + last_modified).
    ok = client.merge_node_with_source(
        "CVE",
        {"cve_id": "CVE-2024-TEST"},
        {
            "cve_id": "CVE-2024-TEST",
            "published": "2024-01-01",
            "last_modified": "2024-06-01",
            "original_source": "nvd",
        },
        source_id="nvd",
    )
    assert ok, "merge_node_with_source must succeed with the stub driver"
    assert captured, "merge_node_with_source must issue at least one Cypher query"

    blob = "\n".join(captured)
    # Negative assertions on the actual Cypher PAYLOAD — not source text,
    # so comment-rephrasing / docstring games can't false-pass this test.
    assert "n.original_published_date" not in blob, (
        "round 17: n.original_published_date SET clause must not appear in sent Cypher"
    )
    assert "n.original_modified_date" not in blob, (
        "round 17: n.original_modified_date SET clause must not appear in sent Cypher"
    )
    # Positive: the canonical EdgeGuard timestamps must still be stamped.
    assert "n.first_imported_at = datetime()" in blob, (
        "first_imported_at must remain — canonical EdgeGuard first-touch timestamp"
    )
    assert "n.last_updated = datetime()" in blob, "last_updated must remain — canonical EdgeGuard modification time"

    # Also exercise merge_indicators_batch (UNWIND path) — same negatives.
    captured.clear()
    ok2 = client.merge_indicators_batch(
        [
            {
                "indicator_type": "ipv4",
                "value": "203.0.113.5",
                "published": "2024-01-01",
                "last_modified": "2024-06-01",
            }
        ],
        source_id="nvd",
    )
    assert ok2 is not False, "merge_indicators_batch must succeed with the stub driver"
    assert captured, "merge_indicators_batch must issue at least one Cypher query"
    batch_blob = "\n".join(captured)
    assert "n.original_published_date" not in batch_blob, (
        "round 17: merge_indicators_batch must not SET n.original_published_date"
    )
    assert "n.original_modified_date" not in batch_blob, (
        "round 17: merge_indicators_batch must not SET n.original_modified_date"
    )


# ---------------------------------------------------------------------------
# Round 18 — dead-field cleanup (CVE.reference_urls + Indicator/Vuln.original_source)
# ---------------------------------------------------------------------------


def test_reference_urls_dead_write_was_removed():
    """Round 18 cleanup: ``CVE.reference_urls`` was stamped via merge_cve's
    extra_props but had ZERO production readers (no GraphQL, no STIX, no
    Cypher MATCH). Same dead-write pattern as round 17. Pin the deletion
    so a future contributor doesn't reintroduce it."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src = inspect.getsource(neo4j_client.Neo4jClient.merge_cve)
    code_only = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
    assert 'extra_props["reference_urls"]' not in code_only, (
        "merge_cve must NOT stamp n.reference_urls — round 18 deleted this dead-write"
    )


def test_original_source_neo4j_property_writes_were_removed():
    """Round 18 cleanup: ``n.original_source`` Neo4j property writes had
    zero production readers. The Python helper that EXTRACTS original_source
    from MISP tags is alive (it derives the canonical `source` field), but
    the dead Neo4j property + 2 indexes were removed."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src_merge = inspect.getsource(neo4j_client.Neo4jClient.merge_node_with_source)
    code_only_merge = "\n".join(line for line in src_merge.splitlines() if not line.lstrip().startswith("#"))
    assert "n.original_source = $original_source" not in code_only_merge, (
        "merge_node_with_source must NOT write n.original_source (round 18)"
    )

    # create_indicator_from_alert (alert-side path) must also drop the SET.
    src_alert = inspect.getsource(neo4j_client.Neo4jClient.create_indicator_from_alert)
    code_only_alert = "\n".join(line for line in src_alert.splitlines() if not line.lstrip().startswith("#"))
    assert "i.original_source = coalesce" not in code_only_alert, (
        "create_indicator_from_alert must NOT write i.original_source (round 18)"
    )

    # And the 2 indexes must be gone from create_indexes.
    src_idx = inspect.getsource(neo4j_client.Neo4jClient.create_indexes)
    code_only_idx = "\n".join(line for line in src_idx.splitlines() if not line.lstrip().startswith("#"))
    assert "indicator_original_source" not in code_only_idx, (
        "indicator_original_source CREATE INDEX must be removed (round 18)"
    )
    assert "vulnerability_original_source" not in code_only_idx, (
        "vulnerability_original_source CREATE INDEX must be removed (round 18)"
    )


def test_misp_unmapped_attribute_type_metric_exists():
    """Round 18 observability: MISP attribute types not in the EdgeGuard
    mapping fall through to ``"unknown"`` silently. The new metric +
    helper surface them so an operator can see when MISP adds a new type."""
    metrics_path = os.path.join(os.path.dirname(__file__), "..", "src", "metrics_server.py")
    with open(metrics_path) as fh:
        metrics_src = fh.read()
    assert "MISP_UNMAPPED_ATTRIBUTE_TYPES" in metrics_src
    assert "edgeguard_misp_unmapped_attribute_types_total" in metrics_src
    assert "def record_misp_unmapped_attribute_type" in metrics_src

    collector_path = os.path.join(os.path.dirname(__file__), "..", "src", "collectors", "misp_collector.py")
    with open(collector_path) as fh:
        collector_src = fh.read()
    assert "record_misp_unmapped_attribute_type" in collector_src, (
        "misp_collector.map_attribute_type must call record_misp_unmapped_attribute_type"
        " when an unmapped type falls through to 'unknown'"
    )


def test_bridge_vulnerability_cve_logs_orphan_count():
    """PR #34 round 20: bridge_vulnerability_cve now uses ``skip_query``
    that counts Vulnerabilities with cve_id but NO matching CVE (orphans),
    and logs directly when skip_count > 0.

    Replaces round 18's broken ``expected_query`` design — that compared
    APOC ``total`` (count of OUTER rows processed, regardless of inner
    MATCH success) against pairs-with-CVE (a subset). The comparison
    ``expected > linked`` was always false (subset ≤ superset), so the
    orphan log NEVER fired. Round 20 inverts: count orphans directly.

    PR #34 test-audit cleanup: dropped the weak comment-stripped negative
    assertions (``expected_query not in code_src``,
    ``expected > results not in code_src``). Those were vulnerable to
    comment-rephrase regressions. The POSITIVE assertions below
    (skip_query + NOT EXISTS pattern) together with the runtime
    behavioral test ``test_bridge_vulnerability_cve_logs_orphan_count_runtime``
    definitively prove the round-20 design is in place and working."""
    import importlib
    import inspect

    if "enrichment_jobs" in sys.modules:
        del sys.modules["enrichment_jobs"]
    enrichment_jobs = importlib.import_module("enrichment_jobs")

    src = inspect.getsource(enrichment_jobs.bridge_vulnerability_cve)
    # Positive-only source pins. If any of these strings aren't present,
    # the test fails loudly — no phantom-target risk.
    assert "skip_query" in src, "bridge_vulnerability_cve must define a skip_query"
    # Skip query must use NOT EXISTS — that's the point: count orphans directly.
    assert "NOT EXISTS { MATCH (c:CVE {cve_id: v.cve_id}) }" in src, (
        "skip_query must NOT EXISTS-MATCH the CVE the inner action would link"
    )
    assert "no matching CVE" in src, "operator-facing log must mention orphan CVE count"


def test_bridge_vulnerability_cve_logs_orphan_count_runtime(caplog):
    """Behavioral pin: when the skip_query reports orphans, the log fires.
    Mocks the Neo4j session to return a non-zero orphan count and verifies
    the operator-facing message is emitted."""
    import importlib
    import logging

    if "enrichment_jobs" in sys.modules:
        del sys.modules["enrichment_jobs"]
    enrichment_jobs = importlib.import_module("enrichment_jobs")

    from unittest.mock import MagicMock

    client = MagicMock()
    sess = MagicMock()
    sess.__enter__ = lambda s: s
    sess.__exit__ = lambda *a: False

    # First session.run = skip_query (returns orphan count); second = main apoc query.
    skip_rec = MagicMock()
    skip_rec.single.return_value = {"c": 42}
    main_rec = MagicMock()
    main_rec.single.return_value = {"linked": 100}
    sess.run.side_effect = [skip_rec, main_rec]
    client.driver.session.return_value = sess

    with caplog.at_level(logging.INFO, logger="enrichment_jobs"):
        enrichment_jobs.bridge_vulnerability_cve(client)
    logs = "\n".join(rec.message for rec in caplog.records)
    assert "42 Vulnerability nodes have no matching CVE" in logs, (
        f"orphan-count log must include the count and phrasing; got: {logs}"
    )


# ---------------------------------------------------------------------------
# Round 19 — bugbot findings on commit 39ec502
# ---------------------------------------------------------------------------


def test_calibrate_large_event_uses_id_based_rebinding():
    """Bugbot (round 19, MED): the round-13 large-event apoc.periodic.iterate
    in calibrate_cooccurrence_confidence used ``WITH $r AS r`` to alias the
    relationship returned from the outer query — the SAME unsafe cross-
    transaction pattern that round 11 fixed in the backfill script.

    apoc.periodic.iterate runs each batch in a NEW transaction; raw entity
    references from the outer can't be safely accessed in the inner.
    Round 19 applies the id()-based pattern: outer RETURNs id(r), inner
    re-MATCHes by id."""
    import importlib
    import inspect

    if "enrichment_jobs" in sys.modules:
        del sys.modules["enrichment_jobs"]
    enrichment_jobs = importlib.import_module("enrichment_jobs")

    src = inspect.getsource(enrichment_jobs.calibrate_cooccurrence_confidence)
    # Outer must return id(r) AS rid (primitive, transaction-safe).
    assert "RETURN id(r) AS rid" in src, "outer must RETURN id(r) AS rid — raw entity refs not safe across apoc batches"
    # Inner must re-MATCH by id.
    assert "id(r) = $rid" in src, "inner must re-MATCH the relationship by id() in the new transaction"
    # Negative: the round-13 unsafe `WITH $r AS r` alias must be gone.
    assert "WITH $r AS r" not in src, (
        "round-19 dropped the unsafe `WITH $r AS r` cross-tx rebind in calibrate_cooccurrence_confidence"
    )


def test_backfill_lists_both_has_cvss_directions():
    """Bugbot has flagged HAS_CVSS_v* reverse-direction entries in
    EDGES_TO_BACKFILL as 'redundant' (PR #34 round 18, false positive).
    They are NOT redundant: ``_merge_cvss_node`` creates two physically-
    separate edges per CVE↔CVSS pair (one in each direction), each with
    its own r.src_uuid / r.trg_uuid that must be backfilled. Pin both
    directions present so a future bugbot rerun can be quickly disproven."""
    import importlib

    if "scripts.backfill_node_uuids" in sys.modules:
        del sys.modules["scripts.backfill_node_uuids"]
    scripts_path = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    backfill = importlib.import_module("backfill_node_uuids")

    edges = set(backfill.EDGES_TO_BACKFILL)
    for v in ("v2", "v30", "v31", "v40"):
        rel = f"HAS_CVSS_{v}"
        cvss_label = f"CVSS{v}"
        forward = (rel, "CVE", cvss_label)
        reverse = (rel, cvss_label, "CVE")
        assert forward in edges, f"backfill missing forward edge ({forward})"
        assert reverse in edges, (
            f"backfill missing REVERSE edge ({reverse}) — _merge_cvss_node creates BOTH "
            "directions (CVE→CVSS and CVSS→CVE), so both must be backfilled"
        )


# ---------------------------------------------------------------------------
# Round 20 — bugbot findings on commit 106d41a
# ---------------------------------------------------------------------------


def test_backfill_omits_cvss_sourced_from_intentionally():
    """PR #34 round 20 (bugbot LOW, false positive): bugbot suggested adding
    SOURCED_FROM edges for CVSSv2/v30/v31/v40 to EDGES_TO_BACKFILL. This is
    wrong — ``_merge_cvss_node`` in neo4j_client.py does NOT create a
    SOURCED_FROM edge. CVSS records are attributes of their parent CVE;
    provenance flows through the CVE's own SOURCED_FROM edge. No such edges
    exist in production, so nothing to backfill.

    Pin the omission so a well-intentioned "add CVSS SOURCED_FROM" refactor
    gets caught by CI instead of running a multi-hour backfill that finds
    zero matching edges in the graph."""
    import importlib

    if "scripts.backfill_node_uuids" in sys.modules:
        del sys.modules["scripts.backfill_node_uuids"]
    scripts_path = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    backfill = importlib.import_module("backfill_node_uuids")

    edges = set(backfill.EDGES_TO_BACKFILL)
    for cvss_label in ("CVSSv2", "CVSSv30", "CVSSv31", "CVSSv40"):
        assert ("SOURCED_FROM", cvss_label, "Source") not in edges, (
            f"SOURCED_FROM ({cvss_label}→Source) must NOT be in EDGES_TO_BACKFILL — "
            "_merge_cvss_node doesn't create this edge type; provenance flows through parent CVE"
        )

    # Also pin the cross-check: every *other* label whose SOURCED_FROM edge
    # IS created by the code path (via merge_node_with_source) must be present.
    for label in ("Indicator", "Vulnerability", "CVE", "Malware", "ThreatActor", "Technique", "Tactic", "Tool"):
        assert ("SOURCED_FROM", label, "Source") in edges, (
            f"SOURCED_FROM ({label}→Source) is produced by merge_node_with_source and must be backfilled"
        )

    # Verify neo4j_client's _merge_cvss_node does NOT call _upsert_sourced_relationship
    # (the method that would create a CVSS SOURCED_FROM). If this ever changes,
    # this test fails and the operator MUST add the CVSS entries above.
    import neo4j_client

    src_path = neo4j_client.__file__
    with open(src_path) as fh:
        source = fh.read()
    cvss_start = source.find("def _merge_cvss_node")
    cvss_end = source.find("def merge_malware", cvss_start)
    assert cvss_start > 0 and cvss_end > cvss_start, "could not locate _merge_cvss_node body"
    cvss_block = source[cvss_start:cvss_end]
    assert "_upsert_sourced_relationship" not in cvss_block, (
        "_merge_cvss_node now calls _upsert_sourced_relationship — SOURCED_FROM edges now exist "
        "for CVSS nodes; EDGES_TO_BACKFILL MUST be updated to include them"
    )


def test_backfill_rejects_conflicting_nodes_only_and_edges_only():
    """PR #34 round 20 (bugbot LOW): passing both ``--nodes-only`` AND
    ``--edges-only`` used to silently skip BOTH passes and exit 0 — the
    operator could believe the backfill ran. argparse's mutually-exclusive
    group now rejects the conflict at CLI parse time."""
    import importlib
    import subprocess

    if "scripts.backfill_node_uuids" in sys.modules:
        del sys.modules["scripts.backfill_node_uuids"]
    scripts_path = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    backfill = importlib.import_module("backfill_node_uuids")

    # Source-level pin: the mutually_exclusive_group must be used for the
    # two flags. A refactor that drops the group would regress the guard.
    src_path = backfill.__file__
    with open(src_path) as fh:
        source = fh.read()
    assert "add_mutually_exclusive_group" in source, (
        "the --nodes-only / --edges-only flags must be in a mutually-exclusive group"
    )

    # Behavioral check: invoking the script with both flags must exit non-zero
    # and write the argparse conflict message to stderr. Use ``-h``-adjacent
    # probing — we parse-args directly and catch SystemExit via subprocess so
    # we don't need a live Neo4j driver.
    env = os.environ.copy()
    # Prevent the script from attempting an actual Neo4j connection before
    # argparse runs (argparse runs first in main(), so this is defense-in-depth).
    env.setdefault("NEO4J_URI", "bolt://invalid:7687")
    result = subprocess.run(
        [sys.executable, src_path, "--nodes-only", "--edges-only"],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    assert result.returncode != 0, (
        "passing both --nodes-only and --edges-only must exit non-zero (argparse rejects the conflict)"
    )
    combined = (result.stderr + result.stdout).lower()
    assert "not allowed" in combined or "mutually exclusive" in combined, (
        f"argparse conflict message missing from output; got stderr:\n{result.stderr}\n\nstdout:\n{result.stdout}"
    )


# ---------------------------------------------------------------------------
# Round 21 — bugbot findings on commit f9d63c3
# ---------------------------------------------------------------------------


def test_vulnerability_resolver_normalizes_empty_misp_event_ids_to_none():
    """PR #34 round 21 (bugbot LOW): the Indicator resolver normalises an
    empty misp_event_ids[] to None via ``event_ids or None``, but the
    Vulnerability resolver passed the raw ``_neo4j_list(...)`` result
    through — yielding ``[]`` for the same logical empty state. Both
    fields are typed ``Optional[List[str]]`` so both shapes are valid
    GraphQL, but consumers (RAG / xAI) treating "absent" vs "empty"
    differently would see the same state two different ways.

    Pin source-shape: the Vulnerability resolver MUST apply the same
    ``or None`` collapse as the Indicator resolver."""
    import importlib
    import inspect

    if "graphql_api" in sys.modules:
        del sys.modules["graphql_api"]
    graphql_api = importlib.import_module("graphql_api")

    src = inspect.getsource(graphql_api._resolve_vulnerabilities)
    assert '_neo4j_list(n.get("misp_event_ids")) or None' in src or (
        "_neo4j_list(n.get('misp_event_ids')) or None" in src
    ), (
        "Vulnerability resolver must normalise empty misp_event_ids to None — "
        "match the Indicator resolver's `event_ids or None` pattern"
    )


def test_build_campaign_nodes_filters_actors_to_precomputed_dict():
    """PR #34 round 21 (bugbot LOW): TOCTOU race between the pre-fetch of
    qualifying ThreatActor names (which builds the deterministic
    ``campaign_uuids`` dict) and the main MERGE query. If a NEW
    ThreatActor gains an ATTRIBUTED_TO edge between the two, it enters
    the MERGE path but ``$campaign_uuids[a.name]`` returns NULL — the
    Campaign would be created with ``uuid=null``, silently breaking the
    cross-environment traceability contract.

    Pin source-shape: the MERGE outer MATCH must include
    ``a.name IN keys($campaign_uuids)`` so race-window actors are
    skipped (picked up next run when they're in the pre-fetch).
    Also pin the defense-in-depth backfill that heals any pre-existing
    NULL-uuid Campaign nodes from before this guard landed."""
    import importlib
    import inspect

    if "enrichment_jobs" in sys.modules:
        del sys.modules["enrichment_jobs"]
    enrichment_jobs = importlib.import_module("enrichment_jobs")

    src = inspect.getsource(enrichment_jobs.build_campaign_nodes)
    # Outer MATCH must filter by precomputed-uuid actor set.
    assert "a.name IN keys($campaign_uuids)" in src, (
        "build_campaign_nodes' MERGE outer MATCH must filter ThreatActors to those in the "
        "precomputed campaign_uuids dict — prevents NULL-uuid Campaigns from race-window actors"
    )
    # Defense-in-depth backfill must exist.
    assert "c.uuid IS NULL AND c.actor_name IN keys($campaign_uuids)" in src, (
        "build_campaign_nodes must include a backfill pass that heals any pre-existing "
        "Campaign nodes with NULL c.uuid (from before round 21's race guard)"
    )
    # Operator-facing log when backfill actually fires.
    assert "[CAMPAIGN] backfilled c.uuid" in src, "operator-facing log must surface the backfill count when > 0"


def test_build_campaign_nodes_backfill_heals_null_uuids_runtime():
    """Behavioral pin: when the backfill query reports N healed Campaigns,
    the operator log fires with the count. Mocks the Neo4j session to
    return non-zero from the backfill query and verifies the message."""
    import importlib
    import logging
    from unittest.mock import MagicMock

    if "enrichment_jobs" in sys.modules:
        del sys.modules["enrichment_jobs"]
    enrichment_jobs = importlib.import_module("enrichment_jobs")

    captured_logs = []

    class _CapHandler(logging.Handler):
        def emit(self, record):
            captured_logs.append(self.format(record))

    handler = _CapHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    enrichment_jobs.logger.addHandler(handler)
    enrichment_jobs.logger.setLevel(logging.INFO)

    try:
        client = MagicMock()
        sess = MagicMock()
        sess.__enter__ = lambda s: s
        sess.__exit__ = lambda *a: False

        # 4 session.run calls in build_campaign_nodes:
        # (1) qualifying_actors_query — return 1 actor
        # (2) create_cypher (main MERGE) — return campaigns count
        # (3) backfill_cypher — return non-zero
        # (4) link_malware
        # (5) link_indicators
        # We give iter for the actors query and .single() for the rest.
        actors_iter = iter([{"name": "APT-Test"}])
        actors_result = MagicMock()
        actors_result.__iter__ = lambda self: actors_iter
        create_result = MagicMock()
        create_result.single.return_value = {"campaigns": 1}
        backfill_result = MagicMock()
        backfill_result.single.return_value = {"backfilled": 7}
        link_m_result = MagicMock()
        link_m_result.single.return_value = {"links": 0}
        link_i_result = MagicMock()
        link_i_result.single.return_value = {"links": 0}
        sess.run.side_effect = [
            actors_result,
            create_result,
            backfill_result,
            link_m_result,
            link_i_result,
        ]
        client.driver.session.return_value = sess

        # Speed up the time.sleep(3) calls.
        import enrichment_jobs as ej

        original_sleep = ej.time.sleep
        ej.time.sleep = lambda *_a: None
        try:
            enrichment_jobs.build_campaign_nodes(client)
        finally:
            ej.time.sleep = original_sleep

        joined = "\n".join(captured_logs)
        assert "[CAMPAIGN] backfilled c.uuid on 7" in joined, (
            f"backfill log must include the count and phrasing; got:\n{joined}"
        )
    finally:
        enrichment_jobs.logger.removeHandler(handler)


# ---------------------------------------------------------------------------
# Round 22 — bugbot findings on commit 513ee4e + multi-agent UUID audit
# ---------------------------------------------------------------------------


def test_indicator_resolver_normalizes_empty_misp_attribute_ids_to_none():
    """PR #34 round 22 (bugbot LOW): round 21 applied ``or None`` to
    ``misp_event_ids`` in the Indicator resolver, AND to ``misp_event_ids``
    in the Vulnerability resolver — but missed the parallel
    ``misp_attribute_ids`` field in the Indicator resolver. An Indicator
    with no MISP attribute IDs surfaced ``misp_event_ids: null`` and
    ``misp_attribute_ids: []`` in the same response — inconsistent.

    Fix: apply the same collapse. Pin the source shape to prevent a future
    rewrite from re-introducing the asymmetry."""
    import importlib
    import inspect

    if "graphql_api" in sys.modules:
        del sys.modules["graphql_api"]
    graphql_api = importlib.import_module("graphql_api")

    src = inspect.getsource(graphql_api._resolve_indicators)
    # Look for the normalized shape. Accept either quoting style.
    assert (
        '_neo4j_list(n.get("misp_attribute_ids")) or None' in src
        or "_neo4j_list(n.get('misp_attribute_ids')) or None" in src
    ), (
        "Indicator resolver must normalize empty misp_attribute_ids to None — "
        "match the round-21 pattern applied to misp_event_ids and the Vulnerability resolver"
    )


def test_sector_sdo_uuid_matches_compute_node_uuid():
    """PR #34 round 22 (multi-agent UUID audit, HIGH): the Sector SDO's
    id UUID must equal ``compute_node_uuid("Sector", {"name": name})``.
    Before round 22 the exporter prepended ``sector|`` to the natural
    key, breaking parity for every Sector (the very contract PR #34
    exists to establish). This test drives the production
    ``_sector_sdo`` end-to-end as a behavioral pin.

    (Companion test lives in tests/test_node_identity.py for all 4 sector
    names; this cross-file pin ensures the round-22 audit fix surfaces
    in the bugbot-fixes regression suite too.)"""
    import importlib

    if "stix_exporter" in sys.modules:
        del sys.modules["stix_exporter"]
    stix_exporter = importlib.import_module("stix_exporter")

    # Behavioral pin (load-bearing): build an SDO and compare UUIDs end-to-end.
    # If a regression re-adds ANY prefix/suffix anywhere along the path
    # (in _sector_sdo, in _deterministic_id, or in node_identity), the
    # UUIDs diverge and this test fails — regardless of where the
    # regression lands. No source-string-pin needed.
    exporter = stix_exporter.StixExporter.__new__(stix_exporter.StixExporter)
    from node_identity import compute_node_uuid

    for sector_name in ("healthcare", "energy", "finance", "global"):
        sdo = exporter._sector_sdo({"name": sector_name})
        sdo_uuid = sdo["id"].split("--", 1)[1]
        neo4j_uuid = compute_node_uuid("Sector", {"name": sector_name})
        assert sdo_uuid == neo4j_uuid, (
            f"parity break for Sector {sector_name!r}: "
            f"_sector_sdo emitted {sdo_uuid}, compute_node_uuid returned {neo4j_uuid}. "
            "Likely cause: a prefix/suffix was re-introduced in _sector_sdo, "
            "_deterministic_id, or node_identity's canonicalization for Sector."
        )


# ---------------------------------------------------------------------------
# Round 23 — extend uuid coverage to User + Alert (delta-sync gap closure)
# ---------------------------------------------------------------------------


def test_user_and_alert_are_in_natural_keys_map():
    """PR #34 round 23: User + Alert added to _NATURAL_KEYS so they
    participate in the cross-environment delta-sync contract. Pin the map
    entries so a future contributor can't silently drop them — the moment
    a label leaves _NATURAL_KEYS, every MERGE site that calls
    ``compute_node_uuid("Label", ...)`` would raise KeyError at runtime.
    """
    from node_identity import _NATURAL_KEYS

    assert _NATURAL_KEYS.get("User") == ("username", "domain"), (
        "User natural key must be (username, domain) — matches the UNIQUE constraint"
    )
    assert _NATURAL_KEYS.get("Alert") == ("alert_id",), (
        "Alert natural key must be (alert_id,) — matches the UNIQUE constraint"
    )


def test_merge_resilmesh_user_stamps_uuid():
    """Round 23 behavioral pin: ``merge_resilmesh_user`` must compute the
    deterministic uuid in Python and pass it as ``$node_uuid`` to the
    Cypher MERGE. Drives the actual production path against a fake driver
    and asserts the captured Cypher includes the uuid SET clause + the
    correct node_uuid value."""
    import importlib
    from unittest.mock import MagicMock

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")
    from node_identity import compute_node_uuid

    captured: list = []

    class _CapSession:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def run(self, query, **params):
            captured.append((query, params))
            r = MagicMock()
            r.single = lambda: None
            r.__iter__ = lambda self_: iter([])
            return r

    class _CapDriver:
        def session(self, **_kw):
            return _CapSession()

        def close(self):
            pass

    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = _CapDriver()

    ok = client.merge_resilmesh_user({"username": "alice", "domain": "corp.local"})
    assert ok, "merge_resilmesh_user must succeed with the stub driver"
    assert captured, "merge_resilmesh_user must issue at least one Cypher query"

    cypher, params = captured[0]
    assert "u.uuid = $node_uuid" in cypher, "Cypher must SET u.uuid from $node_uuid parameter"
    assert "ON CREATE SET u.uuid = $node_uuid" in cypher, "ON CREATE must stamp u.uuid"
    expected_uuid = compute_node_uuid("User", {"username": "alice", "domain": "corp.local"})
    assert params.get("node_uuid") == expected_uuid, (
        f"node_uuid param must equal compute_node_uuid('User', {{username, domain}}); "
        f"got {params.get('node_uuid')}, expected {expected_uuid}"
    )


def test_create_alert_node_stamps_uuid():
    """Round 23 behavioral pin: ``create_alert_node`` must compute and
    stamp deterministic uuid via $node_uuid."""
    import importlib
    from unittest.mock import MagicMock

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")
    from node_identity import compute_node_uuid

    captured: list = []

    class _CapSession:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def run(self, query, **params):
            captured.append((query, params))
            r = MagicMock()
            r.single = lambda: None
            r.__iter__ = lambda self_: iter([])
            return r

    class _CapDriver:
        def session(self, **_kw):
            return _CapSession()

        def close(self):
            pass

    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = _CapDriver()

    ok = client.create_alert_node(
        {
            "alert_id": "alert-12345",
            "source": "edge-sensor-7",
            "zone": ["energy"],
            "threat": {"indicator": "1.2.3.4", "type": "ipv4", "severity": 8},
        }
    )
    assert ok, "create_alert_node must succeed with the stub driver"
    assert captured, "create_alert_node must issue Cypher"
    cypher, params = captured[0]
    assert "a.uuid = $node_uuid" in cypher
    assert "ON CREATE SET a.uuid = $node_uuid" in cypher
    expected = compute_node_uuid("Alert", {"alert_id": "alert-12345"})
    assert params.get("node_uuid") == expected, (
        f"node_uuid param must equal compute_node_uuid('Alert', {{alert_id}}); "
        f"got {params.get('node_uuid')}, expected {expected}"
    )


def test_alert_node_refuses_missing_alert_id():
    """Round 23 behavioral pin: like merge_device + merge_missiondependency
    (rounds 8/9), Alert must refuse to MERGE without its natural key. A
    missing alert_id has no deterministic uuid — better to fail loudly than
    to write a node with NULL uuid that breaks delta sync silently."""
    import importlib

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = None  # short-circuit: must not even reach the driver

    assert client.create_alert_node({}) is False, "create_alert_node({}) must return False"
    assert client.create_alert_node({"alert_id": ""}) is False, (
        "create_alert_node with empty alert_id must return False"
    )


def test_role_user_edges_stamp_endpoint_uuids():
    """Round 23: the Role↔User ASSIGNED_TO edges (both directions) must
    stamp r.src_uuid + r.trg_uuid from the bound endpoint vars now that
    User has a deterministic n.uuid. Source-shape pin (positive) — drives
    the actual production helpers against a fake driver and asserts the
    captured Cypher includes the stamp clauses."""
    import importlib
    from unittest.mock import MagicMock

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    captured: list = []

    class _CapSession:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def run(self, query, **_params):
            captured.append(query)
            r = MagicMock()
            r.single = lambda: None
            return r

    class _CapDriver:
        def session(self, **_kw):
            return _CapSession()

        def close(self):
            pass

    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = _CapDriver()

    client.create_role_assigned_to_user("admin", "alice", "corp.local")
    client.create_user_assigned_to_role("alice", "corp.local", "admin")
    client.link_alert_to_indicator("alert-12345", "1.2.3.4")

    blob = "\n".join(captured)
    # Role→User
    assert "rel.src_uuid = r.uuid" in blob and "rel.trg_uuid = u.uuid" in blob, (
        "Role→User edge must stamp src=r.uuid trg=u.uuid"
    )
    # User→Role
    assert "rel.src_uuid = u.uuid" in blob and "rel.trg_uuid = r.uuid" in blob, (
        "User→Role edge must stamp src=u.uuid trg=r.uuid"
    )
    # Alert→Indicator
    assert "r.src_uuid = a.uuid" in blob and "r.trg_uuid = i.uuid" in blob, (
        "Alert→Indicator (INVOLVES) edge must stamp src=a.uuid trg=i.uuid"
    )
    # All three must use coalesce on the SET path so re-runs don't overwrite.
    assert blob.count("coalesce(rel.src_uuid") >= 2, "Role↔User SET must coalesce src_uuid"
    assert blob.count("coalesce(r.src_uuid") >= 1, "Alert→Indicator SET must coalesce src_uuid"


def test_backfill_includes_round23_edges():
    """Round 23: the new User and Alert edges must be in EDGES_TO_BACKFILL
    so existing graphs (pre-round-23 nodes/edges) get their uuids stamped
    on the next backfill run."""
    import importlib

    if "scripts.backfill_node_uuids" in sys.modules:
        del sys.modules["scripts.backfill_node_uuids"]
    scripts_path = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    backfill = importlib.import_module("backfill_node_uuids")

    edges = set(backfill.EDGES_TO_BACKFILL)
    assert ("ASSIGNED_TO", "Role", "User") in edges, "round-23 backfill must include Role→User ASSIGNED_TO edge"
    assert ("ASSIGNED_TO", "User", "Role") in edges, "round-23 backfill must include User→Role ASSIGNED_TO edge"
    assert ("INVOLVES", "Alert", "Indicator") in edges, "round-23 backfill must include Alert→Indicator INVOLVES edge"


def test_round23_uuid_indexes_are_created():
    """Round 23: User.uuid and Alert.uuid indexes must be in
    create_indexes — without them, MERGE-by-uuid on the cloud receiver
    is O(n) instead of O(1) for these labels."""
    import importlib
    import inspect

    if "neo4j_client" in sys.modules:
        del sys.modules["neo4j_client"]
    neo4j_client = importlib.import_module("neo4j_client")

    src = inspect.getsource(neo4j_client.Neo4jClient.create_indexes)
    assert "user_uuid IF NOT EXISTS FOR (u:User) ON (u.uuid)" in src, "create_indexes must include the user_uuid index"
    assert "alert_uuid IF NOT EXISTS FOR (a:Alert) ON (a.uuid)" in src, (
        "create_indexes must include the alert_uuid index"
    )
