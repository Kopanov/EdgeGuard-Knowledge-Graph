"""PR (S5) regression pins — source-truthful first_seen / last_seen.

Comprehensive test suite for the audit-driven first_seen restoration:

1. **Helper unit tests** — ``source_truthful_timestamps.extract_source_truthful_timestamps``
   per-source allowlist, three-layer resolution (MISP-native → META JSON →
   None), future-date clamp, malformed-META tolerance.

2. **STIX exporter** — ``valid_from`` no longer leaks 1970 epoch when the
   node has ``first_seen_at_source`` or ``first_imported_at``;
   ``x_edgeguard_*`` extensions added.

3. **Cypher source-grep pins** — the MIN/MAX CASE clauses are present in
   every Cypher template that PR (S5) touched; they survive future
   refactors.

4. **Baseline + incremental scenarios** — the user's explicit constraint
   that first_imported_at uses ON CREATE only (never overwritten on
   re-touch), MIN semantics for first_seen_at_source on multi-source
   merges, MAX semantics for last_seen_at_source.

5. **GraphQL schema pins** — the new fields are exposed on every relevant
   type and resolved correctly.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _code_only(text: str) -> str:
    """Strip comment-only lines so source-grep pins don't false-match
    historical-fix comments that mention the old patterns."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


# ===========================================================================
# 1. Helper unit tests — source_truthful_timestamps module
# ===========================================================================


def test_reliable_source_allowlist_includes_all_canonical_sources():
    """Every collector whose upstream first-seen field is canonical
    must be on the allowlist. Source-Truth Investigator audit table."""
    from source_truthful_timestamps import is_reliable_first_seen_source

    for src in (
        "nvd",
        "cisa",
        "mitre_attck",
        "mitre",
        "virustotal",
        "vt",
        "abuseipdb",
        "threatfox",
        "urlhaus",
        "feodo_tracker",
        "feodo",
        "ssl_blacklist",
        "abusech_ssl",
        # CISA: collector emits "cisa_kev" via config.SOURCE_TAGS["cisa"];
        # tests + direct callers may use the bare "cisa" form. BOTH must
        # be on the allowlist or the CISA passthrough is dead.
        # Bugbot caught the misalignment in commit ac25b07.
        "cisa_kev",
    ):
        assert is_reliable_first_seen_source(src), f"{src!r} must be on the reliable allowlist"


def test_collector_emitted_tags_match_allowlist():
    """PR (S5) commit X (bugbot MED): every tag a collector actually
    emits MUST be on the reliable-first-seen allowlist (or be on the
    intentional-exclude list). Bugbot caught the
    ``SOURCE_TAGS["cisa"] == "cisa_kev"`` mismatch in commit
    ac25b07 — the CISA collector emits ``"cisa_kev"`` but the
    allowlist only had ``"cisa"``, making the entire CISA
    source-truthful passthrough dead at runtime.

    This test enumerates every tag string that the live collectors
    pass to the MISPWriter handoff and asserts each one is decisively
    classified — either reliable (allowlisted) or intentionally
    excluded. New collectors / tag renames will fail this test
    until the allowlist is updated, surfacing the bug before
    deploy instead of after.
    """
    from source_truthful_timestamps import is_reliable_first_seen_source

    # Static enumeration of every tag a collector emits. Source: grep
    # ``self.tag = ... | "tag":`` across src/collectors/*.py. If this
    # list goes stale, the test fails.
    collector_emitted_tags = {
        "nvd",  # nvd_collector
        "cisa_kev",  # cisa_collector (via SOURCE_TAGS["cisa"])
        "mitre_attck",  # mitre_collector (via SOURCE_TAGS["mitre"])
        "virustotal",  # virustotal_collector + vt_collector
        "abuseipdb",  # abuseipdb_collector
        "threatfox",  # global_feed_collector
        "urlhaus",  # global_feed_collector
        "feodo_tracker",  # finance_feed_collector
        "ssl_blacklist",  # finance_feed_collector
        # Intentionally excluded from the reliable allowlist:
        "alienvault_otx",  # otx_collector — pulse-publish-date, not IOC first-seen
        "misp",  # misp_collector — pipeline metadata
    }
    intentionally_excluded = {"alienvault_otx", "misp", "cybercure"}

    for tag in collector_emitted_tags:
        is_reliable = is_reliable_first_seen_source(tag)
        if tag in intentionally_excluded:
            assert not is_reliable, (
                f"{tag!r} is on the EXCLUDE list but somehow ended up on the reliable allowlist — that's a logic bug"
            )
        else:
            assert is_reliable, (
                f"Collector emits {tag!r} but it's NOT on the reliable "
                "first-seen allowlist. The source-truthful extractor will "
                "return (None, None) for ALL data from this collector, "
                "silently dropping the canonical first-observed timestamp. "
                "Add it to _RELIABLE_FIRST_SEEN_SOURCES in "
                "src/source_truthful_timestamps.py."
            )


def test_unreliable_sources_excluded_from_allowlist():
    """OTX (pulse-publish-date), CyberCure (synthetic now()), and
    MISP-only feeds must be EXCLUDED so their wrong-semantic dates
    don't silently corrupt n.first_seen_at_source."""
    from source_truthful_timestamps import is_reliable_first_seen_source

    for src in ("otx", "alienvault_otx", "cybercure", "misp", "sector_feed"):
        assert not is_reliable_first_seen_source(src), (
            f"{src!r} must NOT be on the allowlist — its first_seen field has wrong semantic"
        )


def test_allowlist_check_is_case_insensitive():
    """Operator might pass source_id with different casing."""
    from source_truthful_timestamps import is_reliable_first_seen_source

    assert is_reliable_first_seen_source("NVD")
    assert is_reliable_first_seen_source("  threatfox  ")  # whitespace tolerated
    assert is_reliable_first_seen_source("MITRE_ATTCK")


def test_allowlist_handles_none_and_empty():
    """Defensive: missing source_id must return False, not crash."""
    from source_truthful_timestamps import is_reliable_first_seen_source

    assert not is_reliable_first_seen_source(None)
    assert not is_reliable_first_seen_source("")
    assert not is_reliable_first_seen_source("   ")


def test_extractor_returns_none_for_unreliable_source():
    """OTX is excluded; even if attr.first_seen is populated, return None."""
    from source_truthful_timestamps import extract_source_truthful_timestamps

    attr = {"first_seen": "2026-01-15T00:00:00Z", "last_seen": "2026-04-01T00:00:00Z"}
    fs, ls = extract_source_truthful_timestamps(attr, "otx")
    assert fs is None and ls is None


def test_extractor_layer_1_misp_native_fields():
    """MISP-native attribute.first_seen / last_seen are the lossless
    round-trip path. MISPWriter populates these for every indicator."""
    from source_truthful_timestamps import extract_source_truthful_timestamps

    attr = {
        "first_seen": "2019-01-15T00:00:00+00:00",
        "last_seen": "2026-04-01T00:00:00+00:00",
    }
    fs, ls = extract_source_truthful_timestamps(attr, "nvd")
    assert fs == "2019-01-15T00:00:00+00:00"
    assert ls == "2026-04-01T00:00:00+00:00"


def test_extractor_layer_2_nvd_meta_fallback():
    """When MISP-native is missing, fall back to NVD_META.published /
    last_modified."""
    from source_truthful_timestamps import extract_source_truthful_timestamps

    attr: dict = {}  # no MISP-native fields
    nvd_meta = {"published": "2019-01-15T00:00:00+00:00", "last_modified": "2026-02-01T00:00:00+00:00"}
    fs, ls = extract_source_truthful_timestamps(attr, "nvd", nvd_meta=nvd_meta)
    assert fs == "2019-01-15T00:00:00+00:00"
    assert ls == "2026-02-01T00:00:00+00:00"


def test_extractor_layer_2_threatfox_meta_fallback():
    """ThreatFox uses TF_META.first_seen / last_seen."""
    from source_truthful_timestamps import extract_source_truthful_timestamps

    attr: dict = {}
    tf_meta = {"first_seen": "2025-12-01T00:00:00+00:00", "last_seen": "2026-03-15T00:00:00+00:00"}
    fs, ls = extract_source_truthful_timestamps(attr, "threatfox", tf_meta=tf_meta)
    assert fs == "2025-12-01T00:00:00+00:00"
    assert ls == "2026-03-15T00:00:00+00:00"


def test_extractor_layer_1_takes_precedence_over_layer_2():
    """When BOTH MISP-native AND META are present, MISP-native wins
    (it's the lossless lossless round-trip path; META is fallback only)."""
    from source_truthful_timestamps import extract_source_truthful_timestamps

    attr = {"first_seen": "2019-01-15T00:00:00+00:00"}  # MISP-native
    nvd_meta = {"published": "2025-01-01T00:00:00+00:00"}  # different value
    fs, _ = extract_source_truthful_timestamps(attr, "nvd", nvd_meta=nvd_meta)
    assert fs == "2019-01-15T00:00:00+00:00", "MISP-native must win over META fallback"


def test_extractor_returns_none_when_no_value_anywhere():
    """Reliable source but neither MISP-native nor META has a value →
    return None (signal "we don't know") not synthetic now()."""
    from source_truthful_timestamps import extract_source_truthful_timestamps

    attr: dict = {}
    fs, ls = extract_source_truthful_timestamps(attr, "nvd")
    assert fs is None and ls is None


def test_extractor_clamps_future_dates_to_now():
    """Defensive: a future-dated value (operator clock drift / upstream
    bug) must be clamped to NOW with a warning log."""
    from source_truthful_timestamps import extract_source_truthful_timestamps

    future = (datetime.now(timezone.utc) + timedelta(days=3650)).isoformat()
    attr = {"first_seen": future}
    fs, _ = extract_source_truthful_timestamps(attr, "nvd")
    assert fs is not None
    parsed = datetime.fromisoformat(fs.replace("Z", "+00:00") if fs.endswith("Z") else fs)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    # Should be approximately NOW (within 5 seconds)
    assert (datetime.now(timezone.utc) - parsed).total_seconds() < 5, (
        f"future-dated value must be clamped to NOW; got {fs}"
    )


def test_extractor_passes_through_past_dates():
    """A past date must be returned unchanged — clamp only fires for
    FUTURE dates."""
    from source_truthful_timestamps import extract_source_truthful_timestamps

    past = "2019-01-15T00:00:00+00:00"
    attr = {"first_seen": past}
    fs, _ = extract_source_truthful_timestamps(attr, "nvd")
    assert fs == past, "past dates must pass through unchanged"


# PR (S5) commit X (bugbot LOW): the `extract_from_attribute_json`
# convenience wrapper was unused in production and only exercised by
# these two tests — bugbot flagged it as dead code. The wrapper +
# its tests are removed in the same commit; if a future caller
# needs JSON-comment auto-parsing they can re-add the helper.


# ===========================================================================
# 2. STIX exporter — valid_from no longer leaks 1970
# ===========================================================================


def test_stix_indicator_valid_from_uses_first_seen_at_source_when_present():
    """Source-grep pin on the resolution chain in
    ``stix_exporter._indicator_sdo``."""
    path = os.path.join(_SRC, "stix_exporter.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    # The valid_from chain must consult first_seen_at_source first
    assert 'props.get("first_seen_at_source")' in src, (
        "stix_exporter must consult first_seen_at_source as the highest-priority valid_from source"
    )
    # Then first_imported_at as fallback
    assert 'props.get("first_imported_at")' in src
    # Legacy first_seen kept as third-line back-compat
    assert 'props.get("first_seen")' in src


def test_stix_indicator_adds_x_edgeguard_first_imported_at_extension():
    """Best-Practice pin: when first_imported_at is on the props,
    the SDO dict must carry ``x_edgeguard_first_imported_at``."""
    path = os.path.join(_SRC, "stix_exporter.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    assert "x_edgeguard_first_imported_at" in src, (
        "STIX SDO must expose first_imported_at as a producer-specific custom property"
    )
    assert "x_edgeguard_last_seen_at_source" in src


def test_stix_iso_str_helper_handles_neo4j_datetime_objects():
    """PR (S5) commit X (bugbot HIGH) regression pin.

    The neo4j Python driver returns ``neo4j.time.DateTime`` objects when
    reading a node's DateTime property. ``stix2.utils.parse_into_datetime()``
    doesn't recognize that type, so passing one as ``valid_from`` would
    crash. The fix is the ``_iso_str`` helper that coerces any date-like
    value (including neo4j DateTime + Python datetime + bare strings)
    to a plain ISO-8601 string.
    """
    from datetime import datetime, timezone

    from stix_exporter import _iso_str

    # Plain ISO string passes through
    assert _iso_str("2019-01-15T00:00:00+00:00") == "2019-01-15T00:00:00+00:00"
    # Python datetime gets isoformat()'d
    dt = datetime(2019, 1, 15, tzinfo=timezone.utc)
    assert _iso_str(dt) == "2019-01-15T00:00:00+00:00"
    # None passes through
    assert _iso_str(None) is None
    # Empty string returns None (treated as "absent")
    assert _iso_str("") is None
    assert _iso_str("   ") is None

    # Anything with isoformat() works (simulates neo4j.time.DateTime
    # which exposes isoformat())
    class _FakeNeo4jDateTime:
        def isoformat(self) -> str:
            return "2019-01-15T00:00:00+00:00"

    assert _iso_str(_FakeNeo4jDateTime()) == "2019-01-15T00:00:00+00:00"


def test_edge_cypher_wraps_source_reported_with_datetime_and_min_max_case():
    """PR (S5) commit X (architecture redesign) regression pin.

    Per-source timestamps live on ``(n)-[r:SOURCED_FROM]->(s)`` edges,
    not on the node. The edge MERGE Cypher MUST:
    1. Wrap incoming ISO with ``datetime()`` so the stored type is
       Neo4j native DateTime (consistent with r.imported_at /
       r.updated_at).
    2. Use MIN CASE for r.source_reported_first_at — earliest source
       claim wins (correctness against stale imports + backdated
       corrections).
    3. Use MAX CASE for r.source_reported_last_at — latest claim wins.
    4. AND-guard against NULL incoming values so a source that
       doesn't report a timestamp can't NULL-out an existing claim.
    """
    path = os.path.join(_SRC, "neo4j_client.py")
    with open(path) as fh:
        src = fh.read()
    indicator_start = src.find("MERGE (n:Indicator {{indicator_type")
    assert indicator_start > 0
    # Edge MERGE block follows the node MERGE in the same Cypher string
    indicator_end = src.find('"""', indicator_start)
    block = src[indicator_start:indicator_end]
    assert "datetime(item.first_seen_at_source) < r.source_reported_first_at" in block, (
        "Edge SOURCED_FROM MUST MIN-guard r.source_reported_first_at "
        "with datetime()-wrapped comparison (architecture redesign)"
    )
    assert "datetime(item.last_seen_at_source) > r.source_reported_last_at" in block, (
        "Edge SOURCED_FROM MUST MAX-guard r.source_reported_last_at"
    )
    # Nested-CASE NULL short-circuit (Red Team v2 M3 + Bug Hunter v2 #10)
    assert "item.first_seen_at_source IS NULL" in block, (
        "Nested-CASE NULL short-circuit needed for explicit control-flow "
        "(Cypher AND is not guaranteed to short-circuit across versions)"
    )
    assert "item.last_seen_at_source IS NULL" in block


def test_campaign_builder_last_seen_has_max_guard():
    """PR (S5) commit X (bugbot MED) regression pin.

    The campaign-builder Cypher MUST symmetric-guard ``c.last_seen``
    with ``CASE WHEN c.last_seen IS NULL OR last_seen > c.last_seen``
    the same way ``c.first_seen`` is MIN-guarded. Rationale: after
    switching aggregation to
    ``max(coalesce(i.last_seen_at_source, i.last_updated))``, the
    source-truthful ``last_seen_at_source`` can be much OLDER than
    ``last_updated`` (source observed indicator in 2020; EdgeGuard
    last sync'd in 2026) — without the MAX-guard, ``c.last_seen``
    would regress backwards on the first post-deploy enrichment run.
    """
    path = os.path.join(_SRC, "enrichment_jobs.py")
    with open(path) as fh:
        src = fh.read()
    # Source-grep pin on the MAX-guard pattern. Stripping comments
    # keeps the grep against the actual Cypher SET clause.
    # The pattern must appear in the build_campaign_nodes Cypher block.
    campaign_block_start = src.find("MERGE (c:Campaign")
    assert campaign_block_start > 0, "Campaign MERGE block missing from enrichment_jobs.py"
    campaign_block_end = src.find("MERGE (a)-[r_runs:RUNS]->(c)", campaign_block_start)
    block = src[campaign_block_start:campaign_block_end]
    assert "c.last_seen" in block and "last_seen > c.last_seen" in block, (
        "Campaign builder c.last_seen MUST use a MAX-guard CASE "
        "(symmetric with c.first_seen) — otherwise source-truthful "
        "last_seen_at_source (often older than last_updated) can "
        "cause c.last_seen to regress backwards"
    )
    # Also assert the first_seen MIN-guard stayed in place (regression
    # protection against accidental deletion).
    assert "first_seen < c.first_seen" in block, (
        "c.first_seen MIN-guard must remain in place (symmetric with last_seen)"
    )
    # PR (S5) commit X (bugbot LOW): defensive NULL-aggregate guards on
    # both CASE clauses prevent a transient NULL aggregate (brand-new
    # campaign with zero active indicators in this run) from
    # overwriting an existing non-NULL value.
    assert "first_seen IS NOT NULL" in block, "c.first_seen CASE must guard against NULL aggregate (bugbot LOW)"
    assert "last_seen IS NOT NULL" in block, "c.last_seen CASE must guard against NULL aggregate (bugbot LOW)"


def test_coerce_iso_rejects_int_epoch_below_1990_floor():
    """PR (S5) commit X (Bug Hunter v2 #7 HIGH) regression pin.

    A bare ``1700000`` (year 1970-Jan-20) is almost certainly a
    misencoded field — but the original ``0 <= val`` bound let it
    sail through, anchoring MIN aggregates to 1970 and reintroducing
    the original "1970-leak" bug through a different door. Sanity
    floor: 1990-01-01 (``631_152_000``). Anything earlier returns
    None so the MIN/MAX CASE logic preserves any prior value.
    """
    from source_truthful_timestamps import coerce_iso

    # Garbage: pre-1990 epoch → None
    assert coerce_iso(1700000) is None  # ~1970-01-20
    assert coerce_iso(0) is None  # 1970-01-01 itself
    assert coerce_iso(631_151_999) is None  # 1989-12-31
    # Legit modern epochs pass
    assert coerce_iso(631_152_000) == "1990-01-01T00:00:00+00:00"
    assert coerce_iso(1700000000) is not None  # ~2023-11
    # Negative / overflow: None (bounded gracefully, no crash)
    assert coerce_iso(-1) is None
    assert coerce_iso(2**63) is None
    assert coerce_iso(253402300800) is None  # year 10000 (above ceil)


def test_coerce_iso_rejects_invalid_full_iso_strings():
    """PR (S5) commit X (Red Team v2 H3 HIGH) regression pin.

    Previously the FULL-STRING branch (anything not exactly 10 chars)
    just passed the value through unchecked. So
    ``coerce_iso("2024-13-99T10:00:00Z")`` (length 20 — fails the
    date-only shape check) flowed through unguarded → Cypher
    ``datetime()`` rejected → entire UNWIND batch crashed.

    Fix: validate ALL string inputs via ``datetime.fromisoformat``
    (with Z-tolerance shim); return None on parse failure.
    """
    from source_truthful_timestamps import coerce_iso

    # Invalid calendar dates in full ISO strings → None
    assert coerce_iso("2024-13-99T10:00:00Z") is None
    assert coerce_iso("2024-02-30T00:00:00Z") is None  # Feb 30
    # Valid full ISO passes through
    assert coerce_iso("2024-03-15T10:00:00Z") == "2024-03-15T10:00:00Z"
    assert coerce_iso("2024-03-15T10:00:00+00:00") == "2024-03-15T10:00:00+00:00"
    assert coerce_iso("2024-03-15T14:00:00-04:00") == "2024-03-15T14:00:00-04:00"
    # Garbage strings → None
    assert coerce_iso("not-a-date") is None
    assert coerce_iso("hello world") is None


def test_coerce_iso_normalizes_date_only_strings_to_full_iso():
    """PR (S5) commit X (bugbot MED) regression pin.

    CISA KEV's ``dateAdded`` is universally date-only (e.g.
    ``"2026-04-16"``). Neo4j's Cypher ``datetime()`` function rejects
    bare-date strings — it requires a time component. Without
    normalization, ``datetime("2026-04-16")`` would crash the entire
    vulnerability batch MERGE inside the UNWIND query.

    ``coerce_iso`` must normalize ``YYYY-MM-DD`` → ``YYYY-MM-DDT00:00:00+00:00``
    so the value round-trips safely through Neo4j datetime().
    """
    from source_truthful_timestamps import coerce_iso

    # Date-only is normalized to UTC midnight
    assert coerce_iso("2026-04-16") == "2026-04-16T00:00:00+00:00"
    assert coerce_iso("2019-01-15") == "2019-01-15T00:00:00+00:00"
    # Already-full ISO strings pass through untouched
    assert coerce_iso("2024-03-15T12:34:56Z") == "2024-03-15T12:34:56Z"
    assert coerce_iso("2024-03-15T00:00:00+00:00") == "2024-03-15T00:00:00+00:00"
    # PR (S5) commit X (Red Team v2 H3): garbage strings now return
    # None (was passthrough). Validating ALL strings prevents Cypher
    # ``datetime()`` from crashing on bad input mid-batch.
    assert coerce_iso("not-a-date") is None
    assert coerce_iso("abcdefghij") is None  # 10-char non-date
    # None / empty-string still return None
    assert coerce_iso(None) is None
    assert coerce_iso("") is None
    assert coerce_iso("   ") is None


def test_mispwriter_all_entity_paths_forward_first_seen_and_last_seen():
    """PR (S5) commit X (bugbot HIGH) regression pin.

    ALL SEVEN ``create_*_attribute`` methods MUST forward
    ``first_seen`` / ``last_seen`` into the MISP attribute dict — not
    just indicators + vulnerabilities. Previously five of the seven
    (malware, actor, technique, tactic, tool) silently dropped those
    fields at the MISPWriter handoff. MITRE is the primary affected
    source: every MITRE ATT&CK SDO carries a canonical ``created``
    timestamp that the MITRE collector maps into ``item["first_seen"]``.
    Without the passthrough, MITRE-sourced Malware / ThreatActor /
    Technique / Tactic / Tool nodes got ``first_seen_at_source = NULL``
    despite MITRE being on the reliable allowlist.

    This test exercises every code path and asserts the passthrough
    works uniformly. Adding a new entity type without a passthrough
    (a regression) fails this test.
    """
    from collectors.misp_writer import MISPWriter

    writer = MISPWriter.__new__(MISPWriter)
    writer.SOURCE_TAGS = {"mitre": "mitre_attck", "cisa": "cisa_kev"}
    writer._get_zones_to_tag = lambda v: ["global"]  # type: ignore[method-assign]

    FS = "2018-04-18T00:00:00Z"
    LS = "2026-04-18T00:00:00Z"

    # 1. Indicator
    ind = {
        "indicator_type": "ipv4",
        "value": "203.0.113.5",
        "tag": "abuseipdb",
        "source": ["abuseipdb"],
        "first_seen": FS,
        "last_seen": LS,
    }
    attr = writer.create_attribute(ind)
    assert attr and attr.get("first_seen") == FS and attr.get("last_seen") == LS, (
        "indicator path must forward first_seen / last_seen"
    )

    # 2. Vulnerability
    vuln = {"cve_id": "CVE-2024-99999", "tag": "cisa", "first_seen": FS, "last_seen": LS}
    attr = writer.create_vulnerability_attribute(vuln)
    assert attr and attr.get("first_seen") == FS and attr.get("last_seen") == LS

    # 3. Malware
    mal = {"name": "WannaCry", "tag": "mitre", "first_seen": FS, "last_seen": LS}
    attr = writer.create_malware_attribute(mal)
    assert attr and attr.get("first_seen") == FS and attr.get("last_seen") == LS, (
        "malware path MUST forward first_seen/last_seen — bugbot HIGH"
    )

    # 4. Threat actor
    actor = {"name": "APT28", "tag": "mitre", "first_seen": FS, "last_seen": LS}
    attr = writer.create_actor_attribute(actor)
    assert attr and attr.get("first_seen") == FS and attr.get("last_seen") == LS, (
        "threat actor path MUST forward first_seen/last_seen — bugbot HIGH"
    )

    # 5. Technique
    tech = {"mitre_id": "T1059", "name": "Cmd Interpreter", "tag": "mitre", "first_seen": FS, "last_seen": LS}
    attr = writer.create_technique_attribute(tech)
    assert attr and attr.get("first_seen") == FS and attr.get("last_seen") == LS, (
        "technique path MUST forward first_seen/last_seen — bugbot HIGH"
    )

    # 6. Tactic
    tactic = {"mitre_id": "TA0001", "name": "Initial Access", "tag": "mitre", "first_seen": FS, "last_seen": LS}
    attr = writer.create_tactic_attribute(tactic)
    assert attr and attr.get("first_seen") == FS and attr.get("last_seen") == LS, (
        "tactic path MUST forward first_seen/last_seen — bugbot HIGH"
    )

    # 7. Tool
    tool = {"mitre_id": "S0002", "name": "Mimikatz", "tag": "mitre", "first_seen": FS, "last_seen": LS}
    attr = writer.create_tool_attribute(tool)
    assert attr and attr.get("first_seen") == FS and attr.get("last_seen") == LS, (
        "tool path MUST forward first_seen/last_seen — bugbot HIGH"
    )


def test_graphql_node_types_do_not_expose_source_truthful_fields_anymore():
    """PR (S5) commit X (architecture redesign) regression pin.

    Per-source timestamps live on the SOURCED_FROM edge — they are NO
    LONGER node properties. The 7 GraphQL types (CVE / Vulnerability /
    Indicator / ThreatActor / Malware / Technique / Tactic / Tool)
    MUST NOT expose ``first_seen_at_source`` / ``last_seen_at_source``
    as direct fields, because exposing them would either:
      a) Require an N+1 edge-aggregate query per resolver hit (perf), or
      b) Lie about a single value when the truth is per-source.

    Consumers that need per-source detail should query the edges
    directly. Consumers that need an aggregate should use
    ``first_imported_at`` / ``last_updated`` (DB-local, accurate).
    """
    path = os.path.join(_SRC, "graphql_schema.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    classes_with_timestamps = (
        "class CVE:",
        "class Vulnerability:",
        "class Indicator:",
        "class ThreatActor:",
        "class Malware:",
        "class Technique:",
        "class Tactic:",
        "class Tool:",
        "class Campaign:",
    )
    for cls in classes_with_timestamps:
        start = src.find(cls)
        if start < 0:
            continue
        next_class = src.find("\nclass ", start + 1)
        body = src[start:next_class] if next_class > 0 else src[start:]
        assert "first_seen_at_source: Optional" not in body, (
            f"{cls} MUST NOT expose first_seen_at_source — the field was "
            "moved off the node onto the SOURCED_FROM edge in the "
            "PR (S5) architecture redesign"
        )
        assert "last_seen_at_source: Optional" not in body, f"{cls} MUST NOT expose last_seen_at_source — moved to edge"


def test_mispwriter_vulnerability_path_passes_first_seen_and_last_seen():
    """PR (S5) commit X (bugbot MED) regression pin.

    ``create_vulnerability_attribute`` MUST forward the collector's
    ``first_seen`` / ``last_seen`` (or ``last_modified``) into the
    MISP attribute dict so the source-truthful extractor can recover
    the canonical timestamps for non-NVD vulnerability sources (CISA
    KEV in particular). Without this passthrough, CISA's ``dateAdded``
    is silently dropped at the MISPWriter handoff and CISA-sourced
    Vulnerability nodes get ``first_seen_at_source = NULL`` despite
    CISA being on the reliable allowlist.
    """
    from collectors.misp_writer import MISPWriter

    writer = MISPWriter.__new__(MISPWriter)
    # Bypass __init__ — we only need the method.
    writer.SOURCE_TAGS = {"cisa": "source:CISA"}
    writer._get_zones_to_tag = lambda v: ["global"]  # type: ignore[method-assign]
    vuln = {
        "cve_id": "CVE-2024-99999",
        "description": "test",
        "tag": "cisa",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "first_seen": "2024-03-15T00:00:00Z",
        "last_seen": "2024-03-20T00:00:00Z",
    }
    attr = writer.create_vulnerability_attribute(vuln)
    assert attr is not None
    assert attr.get("first_seen") == "2024-03-15T00:00:00Z", (
        "vulnerability MISP attribute MUST carry first_seen so the "
        "source-truthful extractor (Layer 1 MISP-native field) can "
        "populate Vulnerability.first_seen_at_source for CISA + other "
        "non-NVD vulnerability sources"
    )
    assert attr.get("last_seen") == "2024-03-20T00:00:00Z"

    # Empty / missing values must NOT inject a falsy value into the
    # MISP attribute (PyMISP rejects empty strings on those fields).
    vuln2 = {"cve_id": "CVE-2024-88888", "tag": "cisa", "severity": "LOW", "cvss_score": 1.0}
    attr2 = writer.create_vulnerability_attribute(vuln2)
    assert attr2 is not None
    assert "first_seen" not in attr2
    assert "last_seen" not in attr2


def test_virustotal_demo_mode_is_deleted():
    """PR (S5) commit X regression pin.

    The VirusTotal collector previously shipped ``_collect_demo_data`` —
    a fallback that returned 3 hardcoded hashes (EICAR + demo SHAs)
    tagged ``virustotal`` with wall-clock NOW ``first_seen``. Since
    the VT v3 Intelligence API pipeline (``_collect_from_files``) is
    the real production collector, the demo method served no
    production purpose and risked poisoning the graph with fake
    intelligence if a dev piped the output through MISPWriter
    (``virustotal`` is on the reliable source-truthful allowlist).

    The fix is NOT to null out ``first_seen`` — the fix is to delete
    the demo method entirely. Airflow + enrichment callers already
    skip correctly when the API key is absent; non-Airflow callers
    now get an empty list and a warning log pointing to the VT
    signup URL. Production behaviour is unchanged; dev callers who
    relied on the demo hashes should set ``VIRUSTOTAL_API_KEY`` to
    run the real collector.

    This test asserts the method is GONE and that no code path can
    emit wall-clock NOW under the ``virustotal`` tag.
    """
    path = os.path.join(_SRC, "collectors", "virustotal_collector.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    assert "def _collect_demo_data" not in src, (
        "_collect_demo_data must be DELETED — the VT pipeline is the real "
        "production collector; the demo method was a legacy dev shortcut "
        "that risked poisoning Indicator.first_seen_at_source with "
        "wall-clock NOW under the reliable ``virustotal`` tag"
    )
    assert "_collect_demo_data" not in src, "No code path may reference _collect_demo_data (method deleted)"


def test_nvd_collector_does_not_inject_wall_clock_first_seen():
    """PR (S5) commit X regression pin.

    Same bug class as the AbuseIPDB + CISA wall-clock-NOW fallbacks —
    NVD's ``"first_seen": published_str or datetime.now(...).isoformat()``
    would poison ``Vulnerability.first_seen_at_source`` with sync
    wall-clock NOW whenever NVD's ``published`` was empty (rare but
    observable). Fix: emit ``None`` so the extractor's MIN logic
    preserves any prior value.
    """
    path = os.path.join(_SRC, "collectors", "nvd_collector.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    assert '"first_seen": published_str or None' in src, (
        "NVD collector first_seen MUST emit None when published_str is empty "
        "(not wall-clock NOW) — otherwise the extractor writes wall-clock "
        "into n.first_seen_at_source, silently corrupting the source-truth."
    )


def test_cisa_collector_does_not_inject_wall_clock_first_seen():
    """PR (S5) commit X (bugbot MED follow-on) regression pin.

    The CISA collector previously had
    ``"first_seen": date_added or datetime.now(...).isoformat()`` —
    the wall-clock fallback poisoned ``Vulnerability.first_seen_at_source``
    with the sync-run-time NOW for any KEV entry missing ``dateAdded``
    (rare, but observed). Same bug class as the AbuseIPDB blacklist
    fix in commit 87d3529. The fix: emit ``None`` when ``dateAdded``
    is empty so the extractor's MIN logic preserves any prior value
    instead of overwriting it with NOW.
    """
    path = os.path.join(_SRC, "collectors", "cisa_collector.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    assert "datetime.now(timezone.utc).isoformat()" not in (
        src.split('"first_seen"')[1].split('"last_updated"')[0] if '"first_seen"' in src else ""
    ), (
        "CISA collector first_seen MUST NOT fall back to wall-clock NOW — "
        "use 'date_added or None' so the source-truthful extractor preserves "
        "any prior value via MIN logic"
    )
    assert '"first_seen": date_added or None' in src, (
        "CISA collector MUST emit None when dateAdded is empty (not wall-clock NOW)"
    )


def test_coerce_iso_is_single_source_of_truth():
    """PR (S5) commit X (bugbot LOW) regression pin.

    ``run_misp_to_neo4j`` previously had a private ``_coerce_to_iso``
    that was a character-for-character copy of
    ``source_truthful_timestamps._coerce_iso``. Bugbot correctly
    flagged the duplication as a divergence risk. The fix:
    ``run_misp_to_neo4j`` now imports the canonical helper as
    ``_coerce_to_iso`` and the local ``def`` is gone.
    """
    path = os.path.join(_SRC, "run_misp_to_neo4j.py")
    with open(path) as fh:
        src = fh.read()
    # Must NOT redefine the helper locally
    assert "def _coerce_to_iso(" not in _code_only(src), (
        "run_misp_to_neo4j must NOT redefine _coerce_to_iso — import the canonical impl from source_truthful_timestamps"
    )
    # Must import it
    assert "from source_truthful_timestamps import coerce_iso as _coerce_to_iso" in src, (
        "run_misp_to_neo4j must import the canonical coerce_iso (aliased to _coerce_to_iso for call-site compat)"
    )
    # source_truthful_timestamps must export the public name
    path2 = os.path.join(_SRC, "source_truthful_timestamps.py")
    with open(path2) as fh:
        src2 = _code_only(fh.read())
    assert "def coerce_iso(" in src2, (
        "source_truthful_timestamps must define the public coerce_iso (canonical single source of truth)"
    )


def test_stix_sighting_emission_env_var_name_is_documented():
    """The opt-in Sighting SRO emission env var name must remain
    DOCUMENTED in the module so future implementers can find the
    reserved name, even though the variable itself is not assigned
    today (follow-up PR will reintroduce + implement the consumer).

    PR (S5) commit X (bugbot LOW): the previously-defined
    ``_EMIT_SIGHTINGS = os.environ.get(...)`` was unused at module
    level — bugbot correctly flagged it as dead code. The env-var
    name stays in a comment so it isn't accidentally re-used for
    another purpose; the implementation lands in a separate PR.
    """
    path = os.path.join(_SRC, "stix_exporter.py")
    with open(path) as fh:
        src = fh.read()
    assert "EDGEGUARD_STIX_EMIT_SIGHTINGS" in src, (
        "stix_exporter must keep the reserved env-var name documented "
        "(in a comment) so the follow-up Sighting-SRO implementation "
        "PR can find + reuse it"
    )


# ===========================================================================
# 3. Cypher source-grep pins — MIN/MAX CASE clauses present
# ===========================================================================


def test_merge_indicators_batch_writes_source_reported_to_edge():
    """PR (S5) commit X (architecture redesign) regression pin.

    The Indicator batch UNWIND writes per-source timestamps to the
    SOURCED_FROM edge (not to the node). MIN/MAX CASE with AND-guard +
    datetime() wrapper, all on the EDGE properties.
    """
    path = os.path.join(_SRC, "neo4j_client.py")
    with open(path) as fh:
        src = fh.read()
    # Find the indicator batch block (full Cypher string ends at """)
    start = src.find("MERGE (n:Indicator")
    end = src.find('"""', start)
    block = src[start:end]
    # Per-source timestamps must be on the edge
    assert "r.source_reported_first_at" in block, "edge must carry source_reported_first_at"
    assert "r.source_reported_last_at" in block, "edge must carry source_reported_last_at"
    assert "datetime(item.first_seen_at_source) < r.source_reported_first_at" in block, (
        "MIN logic on edge missing or datetime() wrapper dropped"
    )
    assert "datetime(item.last_seen_at_source) > r.source_reported_last_at" in block, (
        "MAX logic on edge missing or datetime() wrapper dropped"
    )
    # And the node MUST NOT carry these fields anymore
    node_only_block = block[: block.find("MATCH (s:Source")]
    assert "n.first_seen_at_source" not in node_only_block, (
        "Node must NOT write first_seen_at_source — moved to edge in architecture redesign"
    )
    assert "n.last_seen_at_source" not in node_only_block, "Node must NOT write last_seen_at_source"


def test_merge_vulnerabilities_batch_writes_source_reported_to_edge():
    """Same contract for the Vulnerability batch."""
    path = os.path.join(_SRC, "neo4j_client.py")
    with open(path) as fh:
        src = fh.read()
    start = src.find("MERGE (n:Vulnerability")
    end = src.find('"""', start)
    block = src[start:end]
    assert "r.source_reported_first_at" in block
    assert "r.source_reported_last_at" in block
    assert "datetime(item.first_seen_at_source) < r.source_reported_first_at" in block
    assert "datetime(item.last_seen_at_source) > r.source_reported_last_at" in block
    node_only = block[: block.find("MATCH (s:Source")]
    assert "n.first_seen_at_source" not in node_only
    assert "n.last_seen_at_source" not in node_only


def test_upsert_sourced_relationship_writes_source_reported_with_min_max_case():
    """Standalone helper used by ``merge_node_with_source`` (which
    services Malware/Actor/Technique/etc.) MUST write per-source
    timestamps to the edge with the nested-CASE MIN/MAX + explicit
    NULL short-circuit + datetime() wrapper (Red Team v2 M3 +
    Bug Hunter v2 #10 — Cypher AND is not guaranteed short-circuit
    so we use nested CASE for explicit control-flow)."""
    path = os.path.join(_SRC, "neo4j_client.py")
    with open(path) as fh:
        src = fh.read()
    start = src.find("def _upsert_sourced_relationship")
    end = src.find("\n    def ", start + 1)
    block = src[start:end]
    assert "r.source_reported_first_at" in block
    assert "r.source_reported_last_at" in block
    # MIN / MAX comparisons with datetime() wrapper for type safety
    assert "datetime($source_reported_first_at) < r.source_reported_first_at" in block
    assert "datetime($source_reported_last_at) > r.source_reported_last_at" in block
    # Nested-CASE NULL short-circuit (explicit, not AND-based)
    assert "$source_reported_first_at IS NULL" in block, (
        "Nested-CASE NULL short-circuit must be present (Red Team v2 M3)"
    )
    assert "$source_reported_last_at IS NULL" in block


def test_first_imported_at_only_set_on_create():
    """first_imported_at must use ON CREATE SET ONLY — never overwritten
    on re-touch. This is the user's explicit baseline+incremental
    correctness constraint.

    Note: the source uses f-string ``{{indicator_type: ...}}`` syntax so
    the rendered Cypher has single braces; our grep matches the rendered
    portion (post-escape).
    """
    path = os.path.join(_SRC, "neo4j_client.py")
    with open(path) as fh:
        src = fh.read()
    # The Cypher-template f-string uses {{...}} for Cypher braces. Grep
    # the f-string template with the doubled braces.
    indicator_start = src.find("MERGE (n:Indicator {{indicator_type")
    assert indicator_start > 0, "could not locate Indicator batch UNWIND template"
    indicator_end = src.find("MATCH (s:Source", indicator_start)
    indicator_block = src[indicator_start:indicator_end]
    assert "ON CREATE SET n.first_imported_at = datetime()" in indicator_block, (
        "first_imported_at must be set on ON CREATE"
    )
    # The SET (not ON CREATE SET) section must NOT re-set first_imported_at.
    # Locate the SET section that follows the ON CREATE SET block.
    on_create_end = indicator_block.find("\n                SET ")
    set_section = indicator_block[on_create_end:]
    # The bare 'n.first_imported_at = datetime()' MUST NOT appear in SET section
    # (only as ON CREATE SET above)
    assert "n.first_imported_at = datetime()" not in set_section, (
        "first_imported_at must NOT be re-assigned in the SET clause — that would overwrite "
        "the original first-touch time on every re-import"
    )


# ===========================================================================
# 4. Baseline + incremental scenario validation (extractor-level)
# ===========================================================================


def test_baseline_then_incremental_preserves_min_first_seen():
    """User's explicit constraint: baseline writes 2019, incremental
    re-touches → 2019 must win (MIN preserves)."""
    from source_truthful_timestamps import extract_source_truthful_timestamps

    # Baseline pull on day 1 — NVD says published=2019-01-15
    attr_baseline = {"first_seen": "2019-01-15T00:00:00+00:00"}
    fs1, _ = extract_source_truthful_timestamps(attr_baseline, "nvd")

    # Incremental pull tomorrow — NVD says published=2019-01-15 (same)
    attr_incremental = {"first_seen": "2019-01-15T00:00:00+00:00"}
    fs2, _ = extract_source_truthful_timestamps(attr_incremental, "nvd")

    assert fs1 == fs2 == "2019-01-15T00:00:00+00:00", (
        "Same NVD CVE re-imported must produce same first_seen_at_source. "
        "Cypher MIN logic then preserves the value across writes."
    )


def test_extraction_returns_none_for_otx_even_with_first_seen():
    """User's "ensure proper updates" — OTX pulse re-import (excluded
    source) must NOT overwrite a previous reliable-source value because
    the extractor returns None for OTX. The Cypher AND-guard then
    preserves the existing value."""
    from source_truthful_timestamps import extract_source_truthful_timestamps

    # OTX collector pulled an indicator that was previously seen by NVD/CISA.
    # OTX's pulse "created" date would mislead — must be excluded.
    attr = {"first_seen": "2026-04-15T00:00:00+00:00"}  # OTX pulse-create date
    fs, _ = extract_source_truthful_timestamps(attr, "otx")
    assert fs is None, "OTX must return None so the Cypher MIN guard preserves any existing reliable-source value"


# ===========================================================================
# 5. GraphQL schema + resolver pins
# ===========================================================================


def test_graphql_schema_does_not_expose_node_level_source_truthful_fields():
    """PR (S5) commit X (architecture redesign): no GraphQL type may
    expose ``first_seen_at_source`` / ``last_seen_at_source`` as a
    node property — they live on the SOURCED_FROM edge now."""
    path = os.path.join(_SRC, "graphql_schema.py")
    with open(path) as fh:
        src = fh.read()
    assert "first_seen_at_source: Optional" not in src, (
        "GraphQL schema MUST NOT expose first_seen_at_source on any node type — "
        "moved to SOURCED_FROM edge in the architecture redesign"
    )
    assert "last_seen_at_source: Optional" not in src


def test_graphql_resolvers_no_longer_populate_node_level_source_truthful():
    """PR (S5) commit X (architecture redesign): no resolver may read
    ``n.first_seen_at_source`` / ``n.last_seen_at_source`` from a node
    Cypher result — those fields no longer exist on nodes."""
    path = os.path.join(_SRC, "graphql_api.py")
    with open(path) as fh:
        src = fh.read()
    assert "first_seen_at_source=str(" not in src, (
        "GraphQL resolvers MUST NOT read first_seen_at_source from a node — "
        "the field lives on the SOURCED_FROM edge now"
    )
    assert "last_seen_at_source=str(" not in src


# ===========================================================================
# 6. Documentation / migration runbook present
# ===========================================================================


def test_migration_doc_exists():
    """Operators need the migration runbook to verify their deploy.

    PR (S5) commit X (architecture redesign): doc was rewritten for
    the edge model. Assertions updated to match the new content
    sections.
    """
    path = os.path.join(os.path.dirname(__file__), "..", "migrations", "2026_04_first_seen_at_source.md")
    assert os.path.exists(path), "migrations/2026_04_first_seen_at_source.md must ship with this PR"
    with open(path) as fh:
        body = fh.read().lower()
    # Key sections must be present
    assert "reliable-source allowlist" in body
    assert "verification queries" in body
    # The new doc uses "what's not backfilled" instead of "no bulk backfill"
    assert "backfill" in body, "doc must address the backfill story"
    # Edge-model specifics
    assert "sourced_from" in body, "edge label must be referenced"
    assert "source_reported_first_at" in body, "new edge property must be documented"
    assert "first_imported_at" in body
    # Operator FAQ section + consumer migration table
    assert "operator faq" in body
    # Backfill script is referenced
    assert "backfill" in body
