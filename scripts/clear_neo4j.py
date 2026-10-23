#!/usr/bin/env python3
"""
EdgeGuard - Clear Neo4j Data Script

Deletes EdgeGuard's graph data from Neo4j; constraints and indexes stay.

By default it deletes only the nodes EdgeGuard created (``edgeguard_managed = true``) and the
relationships attached to them, through the wipe of the fresh baseline
(``baseline_clean._wipe_neo4j`` and ``Neo4jClient.clear_edgeguard_managed``). Nodes another system
created on a shared database (ResilMesh topology, a scanner's ``Vulnerability`` and ``CVE`` nodes)
stay, also where EdgeGuard enriched them. ``--label`` narrows the delete to the EdgeGuard-created
nodes of one label. ``--full-wipe`` deletes every node in the database (``Neo4jClient.clear_all``)
after a warning that counts the nodes EdgeGuard did not create and a typed confirmation, also with
``--force``. Every delete appends a line to the destructive-operations audit trail
(``src/destructive_ops_audit.py``), also a delete that fails part-way (``details.outcome =
"failed"``, with what it deleted); a successful delete also clears the collector checkpoints.

Usage:
    python3 scripts/clear_neo4j.py --dry-run               # preview the scope, delete nothing
    python3 scripts/clear_neo4j.py --force                 # delete the EdgeGuard-created nodes
    python3 scripts/clear_neo4j.py --label Indicator       # only the EdgeGuard-created Indicator nodes
    python3 scripts/clear_neo4j.py --full-wipe             # every node; asks to type FULL-WIPE
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import argparse
import logging
from typing import Dict, List, Optional

import baseline_clean
from neo4j_client import Neo4jClient

logger = logging.getLogger(__name__)

# Typed answer that confirms a whole-database delete (--full-wipe, with or without --force).
FULL_WIPE_CONFIRMATION = "FULL-WIPE"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Delete EdgeGuard's graph data from Neo4j: by default the nodes EdgeGuard created "
            "(edgeguard_managed = true) and their relationships; partner data on a shared database stays."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 clear_neo4j.py --dry-run               # Preview what would be deleted and what stays
  python3 clear_neo4j.py --force                 # Delete the nodes EdgeGuard created
  python3 clear_neo4j.py --label Indicator       # Delete only the EdgeGuard-created Indicator nodes
  python3 clear_neo4j.py --full-wipe             # Delete EVERY node, partner data included (asks first)
        """,
    )
    parser.add_argument("--dry-run", "-n", action="store_true", help="Show what would be deleted without deleting")
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Delete the EdgeGuard-created nodes",
    )
    parser.add_argument(
        "--label", "-l", type=str, help="Delete only the EdgeGuard-created nodes of this label (no --force needed)"
    )
    parser.add_argument("--no-recreate", action="store_true", help="Do not recreate Source nodes after clearing")
    parser.add_argument(
        "--full-wipe",
        action="store_true",
        help=(
            "Delete EVERY node and relationship in the database, including the nodes other systems created on a "
            f"shared database; asks to type {FULL_WIPE_CONFIRMATION}, also with --force"
        ),
    )
    return parser


def _scope_lines(counts: Dict[str, int], label: Optional[str], full_wipe: bool) -> List[str]:
    """What the run deletes and what stays, from ``Neo4jClient.count_edgeguard_managed``."""
    managed, others, enriched = counts["managed"], counts["others"], counts["enriched"]
    if full_wipe:
        return [
            f"In scope: EVERY node in the database, {managed + others:,} node(s), and every relationship.",
            f"WARNING: {others:,} of them EdgeGuard did not create (data of other systems on a shared database, "
            f"such as ResilMesh topology and scanner CVE / Vulnerability nodes; {enriched:,} enriched by EdgeGuard) "
            "and are deleted as well.",
        ]
    kind = "node(s)" if label is None else f"{label} node(s)"
    return [
        f"In scope: {managed:,} {kind} EdgeGuard created (edgeguard_managed = true) and their relationships.",
        f"Kept: {others:,} {kind} EdgeGuard did not create ({enriched:,} of them enriched by EdgeGuard).",
    ]


def _confirm_full_wipe() -> bool:
    try:
        answer = input(f"This deletes EVERY node in the database. Type {FULL_WIPE_CONFIRMATION} to confirm: ")
    except EOFError:
        answer = ""
    return answer.strip() == FULL_WIPE_CONFIRMATION


def clear(
    client: Neo4jClient,
    *,
    dry_run: bool = False,
    full_wipe: bool = False,
    label: Optional[str] = None,
    recreate_sources: bool = True,
) -> int:
    """Preview, confirm and delete; returns the exit code. ``client`` must be connected."""
    try:
        counts = client.count_edgeguard_managed(label)
    except ValueError as exc:
        print(f"Refused: {exc}. Nothing was deleted.")
        return 1
    except Exception as exc:
        logger.error("Cannot count the nodes in scope (%s: %s); nothing was deleted.", type(exc).__name__, exc)
        return 1

    for line in _scope_lines(counts, label, full_wipe):
        print(line)

    if dry_run:
        print("Dry run: nothing was deleted.")
        return 0

    if full_wipe and not _confirm_full_wipe():
        print("Aborted: the confirmation did not match. Nothing was deleted.")
        return 1

    scope = baseline_clean.WIPE_SCOPE_ALL if full_wipe else baseline_clean.WIPE_SCOPE_EDGEGUARD
    try:
        baseline_clean._wipe_neo4j(client, scope, label=label)
    except Exception as exc:
        logger.error("Neo4j clear failed (%s: %s); the collector checkpoints are kept.", type(exc).__name__, exc)
        return 1
    print("Neo4j cleared (constraints and indexes kept).")

    if recreate_sources and label is None:
        if client.ensure_sources():
            print("Source nodes recreated.")
        else:
            logger.warning("Source nodes were not recreated; run: python src/neo4j_client.py --bootstrap-sources")

    # Clear the checkpoint file so the MITRE ETag and the other cursors are reset (full reset).
    try:
        from baseline_checkpoint import clear_checkpoint

        clear_checkpoint(include_incremental=True)
        print("Cleared the baseline checkpoints and the incremental cursors.")
    except Exception as exc:
        logger.warning("Could not clear the checkpoints: %s", exc)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point; returns the exit code."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.label is not None and args.full_wipe:
        parser.error(
            "--label narrows the delete of the EdgeGuard-created nodes; it cannot be combined with --full-wipe"
        )

    # Require an explicit action
    if not (args.dry_run or args.force or args.label is not None or args.full_wipe):
        parser.print_help()
        print(
            "\nNo action specified. Use --dry-run to preview, --force to delete the nodes EdgeGuard created, "
            "--label for one label, or --full-wipe for every node."
        )
        return 1

    client = Neo4jClient()
    if not client.connect():
        logger.error("Failed to connect to Neo4j. Exiting.")
        return 1
    try:
        return clear(
            client,
            dry_run=args.dry_run,
            full_wipe=args.full_wipe,
            label=args.label,
            recreate_sources=not args.no_recreate,
        )
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
