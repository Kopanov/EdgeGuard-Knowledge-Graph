#!/usr/bin/env python3
"""
PR-N32 — Read-only audit: legacy unicode-bypass nodes in Neo4j.

## Why this script exists

PR-N29 L1 + PR-N31 closed 35 zero-width / bidi-control / variation-
selector chars in ``is_placeholder_name`` so an attacker (or buggy
upstream feed) can no longer create ``Malware``/``ThreatActor``/``Tool``
nodes whose ``name`` is a placeholder ("unknown", "n/a", …) padded with
invisible chars. **However**: nodes that were MERGEd BEFORE PR-N29 L1
(i.e., older than 2026-04-24) bypassed the filter and may still exist
in production Neo4j with names like ``"unknown​"``,
``"unknown‎"``, etc.

This script answers a single question: **how many such nodes exist
right now in the connected Neo4j**, so the operator can decide whether
PR-N32 (a destructive cleanup PR) is needed at all.

| Audit result          | Implication                                                |
|-----------------------|------------------------------------------------------------|
| 0 suspicious nodes    | PR-N32 cleanup not needed; close as a no-op                |
| 1–10 suspicious       | Manual rename / re-merge in a one-shot Cypher; no PR needed |
| > 10 suspicious       | Build a proper migration: rename / re-merge / hard delete  |

The script is **strictly read-only** — opens a Neo4j session in
``READ_ACCESS`` mode so a future-maintainer drift (e.g. someone adding
a stray MERGE) fails with a loud ``neo4j.exceptions.ClientError``
instead of silently mutating production.

## Single source of truth

The list of "suspicious" characters is imported directly from
``src/node_identity._ZERO_WIDTH_AND_BIDI_CHARS`` — the same canonical
list ``is_placeholder_name`` strips. If a future PR adds chars to that
list, this audit picks them up automatically without a separate update.

## Usage

    export NEO4J_URI="bolt://localhost:7687"
    export NEO4J_PASSWORD="<password>"
    export NEO4J_USER="neo4j"  # optional, defaults to neo4j

    # Default: count + sample 5 names per label.
    ./scripts/audit_legacy_unicode_bypass_nodes.py

    # More samples for triage.
    ./scripts/audit_legacy_unicode_bypass_nodes.py --sample-limit 20

    # Quiet mode — just the JSON summary on stdout for piping.
    ./scripts/audit_legacy_unicode_bypass_nodes.py --json

Exit codes:
    0 — audit ran successfully (regardless of finding count)
    1 — connection / config error (operator-actionable)

The audit NEVER exits non-zero on "found N suspicious nodes" — that's
informational, not a CI failure. If you want a CI gate based on the
count, parse the JSON output: ``--json | jq '.total_suspicious'``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

# Make src/ importable so we can pull the canonical char list from
# node_identity (single source of truth — see module docstring).
SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from neo4j import READ_ACCESS, Driver, GraphDatabase  # noqa: E402
from node_identity import _ZERO_WIDTH_AND_BIDI_CHARS  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# Labels that use ``name`` as natural key + are subject to placeholder
# filtering via ``is_placeholder_name`` (see neo4j_client.merge_malware /
# merge_actor / merge_tool). Sectors are excluded — Sector names are
# operator-controlled (config), not feed-derived.
_AUDITED_LABELS = ("Malware", "ThreatActor", "Tool")


def _build_suspicious_regex() -> str:
    """Return a Cypher-compatible regex matching any of the canonical
    zero-width / bidi-control / variation-selector chars.

    Cypher uses Java regex syntax. We use the inline ``\\uXXXX`` escapes
    rather than a literal char class so the regex is greppable and
    doesn't depend on the source file's encoding.

    Single source of truth: pulls from
    ``node_identity._ZERO_WIDTH_AND_BIDI_CHARS`` — if a future PR adds
    chars there, this audit picks them up automatically."""
    escapes = "".join(f"\\u{ord(c):04x}" for c in _ZERO_WIDTH_AND_BIDI_CHARS)
    return f".*[{escapes}].*"


_SUSPICIOUS_REGEX = _build_suspicious_regex()


def _count_query(label: str) -> str:
    """Cypher to count + sample suspicious nodes for one label.

    Returns three things:
    * ``total`` — total nodes of this label (for context — what % is suspicious)
    * ``suspicious`` — count of nodes whose ``name`` matches the regex
    * ``samples`` — first N suspicious node names (for operator triage)

    The label is interpolated server-side because Cypher doesn't support
    parameterised label names — we control the input via ``_AUDITED_LABELS``
    so injection is not a vector."""
    return f"""
    MATCH (n:{label})
    WITH count(n) AS total,
         collect(CASE WHEN n.name =~ $regex THEN n.name END) AS all_names
    UNWIND all_names AS name
    WITH total, name
    WHERE name IS NOT NULL
    WITH total, collect(name) AS suspicious_names
    RETURN total,
           size(suspicious_names) AS suspicious,
           suspicious_names[0..$sample_limit] AS samples
    """


def _annotate_codepoints(name: str) -> str:
    """Render a name with its non-ASCII codepoints visible.

    A raw ``"unknown​"`` printed to terminal looks identical to
    ``"unknown"`` — operator can't visually identify the problem. This
    helper renders each non-printable as ``<U+200B>`` so the bypass is
    obvious in the audit output."""
    out_parts = []
    for c in name:
        if ord(c) < 128 and c.isprintable():
            out_parts.append(c)
        else:
            out_parts.append(f"<U+{ord(c):04X}>")
    return "".join(out_parts)


def get_driver() -> Driver:
    """Connect using NEO4J_URI / NEO4J_PASSWORD / NEO4J_USER from env.
    Mirrors ``scripts/backfill_edge_misp_event_ids.py`` for consistency."""
    uri = os.environ.get("NEO4J_URI")
    password = os.environ.get("NEO4J_PASSWORD")
    if not uri:
        logger.error("NEO4J_URI not set — required (e.g. bolt://localhost:7687)")
        sys.exit(1)
    if not password:
        logger.error("NEO4J_PASSWORD not set — required")
        sys.exit(1)
    user = os.environ.get("NEO4J_USER", "neo4j")
    return GraphDatabase.driver(uri, auth=(user, password))


def audit_label(driver: Driver, label: str, sample_limit: int) -> Dict[str, Any]:
    """Run the count + sample query for one label.

    READ_ACCESS at session level — guarantees no write can sneak in even
    if the query string is later modified (e.g. by a future maintainer
    adding a stray MERGE). Server rejects writes with
    ``neo4j.exceptions.ClientError`` — loud failure beats silent
    corruption."""
    with driver.session(default_access_mode=READ_ACCESS) as session:
        result = session.run(
            _count_query(label),
            regex=_SUSPICIOUS_REGEX,
            sample_limit=sample_limit,
        )
        record = result.single()
        if record is None:
            return {"label": label, "total": 0, "suspicious": 0, "samples": []}
        return {
            "label": label,
            "total": int(record["total"]),
            "suspicious": int(record["suspicious"]),
            "samples": list(record["samples"] or []),
        }


def render_human(per_label: List[Dict[str, Any]]) -> str:
    """Operator-facing summary — column-aligned + codepoint-annotated."""
    lines = ["", "=== Audit: Legacy unicode-bypass nodes ===", ""]
    total_suspicious = 0
    for row in per_label:
        lines.append(
            f"[{row['label']:<14}] total_nodes={row['total']:>10,}   "
            f"suspicious={row['suspicious']:>4}" + ("   (all clean)" if row["suspicious"] == 0 else "")
        )
        if row["samples"]:
            lines.append("  Samples (codepoints expanded):")
            for s in row["samples"]:
                lines.append(f"    - {_annotate_codepoints(s)!r}")
        total_suspicious += row["suspicious"]

    lines.append("")
    lines.append(f"Total suspicious: {total_suspicious}")
    lines.append("")

    if total_suspicious == 0:
        lines.append("RECOMMENDATION: PR-N32 cleanup is NOT needed — close it as a no-op.")
        lines.append("")
        lines.append("All node names are clean of the canonical zero-width / bidi-")
        lines.append("control / variation-selector char set. The PR-N29 L1 + PR-N31")
        lines.append("filter is doing its job for new MERGEs, and there is no legacy")
        lines.append("backlog to clean up.")
    elif total_suspicious <= 10:
        lines.append(f"RECOMMENDATION: {total_suspicious} suspicious nodes — manual one-shot Cypher.")
        lines.append("")
        lines.append("Small enough to fix by hand. For each sample above, decide:")
        lines.append("  * RENAME — operator-canonical name is obvious; ``SET n.name = ...``")
        lines.append("  * RE-MERGE — find the canonical node + ``CALL apoc.refactor.mergeNodes(...)``")
        lines.append("  * DELETE — node has no real edges; ``MATCH (n) WHERE elementId(n)=... DETACH DELETE n``")
        lines.append("")
        lines.append("No need for a migration PR — keep it as a one-shot in")
        lines.append("docs/MIGRATIONS.md with a date stamp + the count above.")
    else:
        lines.append(f"RECOMMENDATION: {total_suspicious} suspicious nodes — full PR-N32 migration warranted.")
        lines.append("")
        lines.append("Open PR-N32 with:")
        lines.append("  1. A reusable cleanup script under scripts/ (mirrors")
        lines.append("     backfill_edge_misp_event_ids.py — --dry-run + --commit modes,")
        lines.append("     READ_ACCESS in dry-run, idempotency guard).")
        lines.append("  2. Policy decision tree (rename / re-merge / delete) per pattern.")
        lines.append("  3. Docs/MIGRATIONS.md entry + RUNBOOK pointer.")
        lines.append("  4. Behavioural test on a fake driver (no live Neo4j needed in CI).")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PR-N32 — read-only audit of legacy unicode-bypass nodes in Neo4j.")
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=5,
        help="How many suspicious node names to sample per label (default: 5).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON on stdout instead of human summary.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    driver = get_driver()
    try:
        per_label = [audit_label(driver, label, args.sample_limit) for label in _AUDITED_LABELS]
    finally:
        # finally before the broad rendering: no NameError-mask risk because
        # ``driver`` is already bound by this point (get_driver sys.exit's on failure).
        driver.close()

    if args.json:
        # Machine-readable for CI / piping. Schema is stable: any change
        # here MUST update the test in tests/test_pr_n32_unicode_audit.py.
        payload = {
            "schema_version": 1,
            "per_label": per_label,
            "total_suspicious": sum(r["suspicious"] for r in per_label),
            "audited_labels": list(_AUDITED_LABELS),
            "char_count_in_filter": len(_ZERO_WIDTH_AND_BIDI_CHARS),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(render_human(per_label))
    return 0


if __name__ == "__main__":
    sys.exit(main())
