#!/usr/bin/env python3
"""EdgeGuard alert enrichment demo (2026-10).

Runs EdgeGuard's own alert enrichment (``src/alert_processor.py``,
``AlertProcessor.enrich_alert_read_only``) against the Neo4j database named by ``NEO4J_URI``,
``NEO4J_USER`` and ``NEO4J_PASSWORD`` and prints each response as JSON, exactly as the processor
returns it. Nothing in the output is invented: every value comes from the graph or the alert, or
is derived from them by the processor (the recommendations), or is the processor's own (version,
measured latency).

The demo never writes: ``enrich_alert_read_only`` skips the steps of ``process_alert`` that
record the alert. Apart from ``Neo4jClient``'s connection check (``RETURN 1``, in a session of the
default access mode), every statement is a MATCH / RETURN query sent in a read access session: the
enrichment's queries and, with ``--from-graph``, the selection query below.

The alert is handed to the processor directly: no NATS server is involved (EdgeGuard has no
deployed NATS consumer yet). Usage: ``--help`` and ``docs/DEMO.md``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")

# The read-only selection of --from-graph: active indicators that INDICATE a malware family, the
# most recently updated first. ``$zone`` is null without --zone.
SELECTION_QUERY = """MATCH (i:Indicator)
WHERE i.active = true
  AND ($zone IS NULL OR $zone IN coalesce(i.zone, []))
  AND EXISTS { MATCH (i)-[:INDICATES]->(:Malware) }
RETURN i.value AS value, i.indicator_type AS indicator_type, i.zone AS zone
ORDER BY i.last_updated DESC, i.value
LIMIT $limit"""

SELECTION_TIMEOUT_SECONDS = 120.0

EXIT_OK = 0
# Neo4j unreachable, credentials refused, the selection query failed, or (2026-10) an enrichment
# query failed: the parts not read yet then hold the processor's defaults, as if the graph held
# nothing.
EXIT_NEO4J = 1
# Bad arguments, unreadable alert file, incomplete configuration, or (2026-10) an alert the
# processor raised on (e.g. a non-string ``threat.cve``).
EXIT_USAGE = 2
EXIT_NOTHING_SELECTED = 3  # --from-graph found no indicator to enrich

_HELP_EPILOG = f"""\
The alerts come from a JSON file (one alert object, or a list of them, in the
ResilMesh alert schema of src/alert_processor.py) or, with --from-graph N, are
built from N real indicators selected by this read-only query:

{SELECTION_QUERY}

Each built alert carries the indicator's value and type, its first stored zone
other than "global" (or the --zone given), the time it was built, an alert id
"demo-graph-<n>" and the source "edgeguard-demo"; no malware, CVE or host field
is added.

Connection: NEO4J_URI (default bolt://localhost:7687), NEO4J_USER (default
neo4j), NEO4J_PASSWORD. src/config.py also requires MISP_API_KEY to be set when
it is imported; the demo does not contact MISP.

Output: a JSON array of responses on stdout; progress and errors on stderr.
A response whose enrichment query failed is printed with enriched: false and
query_metadata.error, and its alert id is named on stderr. An alert the
processor raises on is left out of the array and named on stderr.
Exit codes: 0 done; 1 Neo4j unreachable, the selection query failed or an
enrichment query failed; 2 usage or configuration error, or an alert the
processor raised on; 3 --from-graph selected no indicator.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alert_enrichment_demo.py",
        description=(
            "Enrich ResilMesh alerts with EdgeGuard's alert enrichment (src/alert_processor.py), "
            "read-only, against the configured Neo4j, and print the responses as JSON."
        ),
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--alerts", metavar="FILE", help="JSON file holding one alert object or a list of alerts")
    source.add_argument(
        "--from-graph",
        metavar="N",
        type=int,
        help="build N alerts from active indicators that have an INDICATES link (query below)",
    )
    parser.add_argument(
        "--zone",
        help="with --from-graph: only indicators whose zone list holds this zone (healthcare, energy, finance, global)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log at INFO level on stderr")
    return parser


def build_alert_from_indicator(
    row: Mapping[str, Any], number: int, built_at: str, zone: Optional[str] = None
) -> Dict[str, Any]:
    """A ResilMesh alert for one selected indicator, holding only what the graph says about it."""
    stored = row.get("zone")
    zones = [stored] if isinstance(stored, str) else [z for z in (stored or []) if isinstance(z, str) and z]
    specific = [z for z in zones if z != "global"]
    return {
        "alert_id": f"demo-graph-{number}",
        "source": "edgeguard-demo",
        "zone": zone or (specific[0] if specific else "global"),
        "timestamp": built_at,
        "threat": {
            "indicator": row.get("value"),
            "type": row.get("indicator_type") or "unknown",
            "description": "Alert built by demo/alert_enrichment_demo.py from an indicator in the graph",
        },
    }


def select_indicators(driver: Any, limit: int, zone: Optional[str], read_access: str) -> List[Dict[str, Any]]:
    """Run ``SELECTION_QUERY`` in a read session and return its rows."""
    with driver.session(default_access_mode=read_access) as session:
        result = session.run(SELECTION_QUERY, {"limit": limit, "zone": zone}, timeout=SELECTION_TIMEOUT_SECONDS)
        return [dict(record) for record in result]


def load_alerts(path: str) -> List[Dict[str, Any]]:
    """The alerts of a JSON file: one alert object or a list of alert objects."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    alerts = data if isinstance(data, list) else [data]
    for index, item in enumerate(alerts):
        if not isinstance(item, dict):
            raise ValueError(f"item {index} of {path} is not a JSON object")
    if not alerts:
        raise ValueError(f"{path} holds no alert")
    return alerts


def _connect_once(client: Any) -> bool:
    """One connection attempt. ``Neo4jClient.connect`` retries five times with backoff (about a
    minute) for the pipeline; a presenter needs to know at once that the database is unreachable."""
    connect = getattr(type(client).connect, "__wrapped__", None)
    return bool(connect(client) if connect is not None else client.connect())


def _err(message: str) -> None:
    print(message, file=sys.stderr)


def main(argv: Optional[Sequence[str]] = None, client_factory: Optional[Callable[[], Any]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.from_graph is not None and args.from_graph < 1:
        parser.error("--from-graph needs a positive number")
    if args.zone and args.from_graph is None:
        parser.error("--zone applies to --from-graph only")

    # Before src is imported: alert_processor's logging.basicConfig is then a no-op and stdout
    # carries the JSON only.
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, stream=sys.stderr)

    if _SRC not in sys.path:
        sys.path.insert(0, _SRC)
    try:
        from alert_processor import AlertProcessor
        from config import VALID_ZONES
        from neo4j import READ_ACCESS
        from neo4j_client import Neo4jClient
    except RuntimeError as exc:  # src/config.py: a required environment variable is missing
        _err(f"Configuration incomplete: {exc}")
        return EXIT_USAGE

    if args.zone and args.zone not in VALID_ZONES:
        _err(f"Unknown zone {args.zone!r}; valid zones: {', '.join(sorted(VALID_ZONES))}")
        return EXIT_USAGE

    alerts: List[Dict[str, Any]] = []
    if args.alerts:
        try:
            alerts = load_alerts(args.alerts)
        except (OSError, ValueError) as exc:  # json.JSONDecodeError is a ValueError
            _err(f"Cannot read alerts: {exc}")
            return EXIT_USAGE

    client = (client_factory or Neo4jClient)()
    uri = getattr(client, "uri", "the configured Neo4j")
    try:
        connected = _connect_once(client)
    except Exception as exc:  # noqa: BLE001 - every connection failure ends the demo the same way
        _err(f"Neo4j at {uri} is unreachable ({type(exc).__name__}: {exc})")
        return EXIT_NEO4J
    if not connected:
        _err(f"Neo4j at {uri} refused the connection or the credentials (details in the log above)")
        return EXIT_NEO4J

    try:
        if args.from_graph is not None:
            try:
                rows = select_indicators(client.driver, args.from_graph, args.zone, READ_ACCESS)
            except Exception as exc:  # noqa: BLE001 - reported, not raised, for a presenter
                _err(f"The selection query failed ({type(exc).__name__}: {exc})")
                return EXIT_NEO4J
            if not rows:
                _err("No active indicator with an INDICATES link" + (f" in zone {args.zone}" if args.zone else ""))
                return EXIT_NOTHING_SELECTED
            built_at = datetime.now(timezone.utc).isoformat()
            alerts = [build_alert_from_indicator(row, n, built_at, args.zone) for n, row in enumerate(rows, 1)]
            _err(f"Selected {len(alerts)} indicator(s) with the query shown by --help")

        processor = AlertProcessor(neo4j_client=client)
        responses: List[Dict[str, Any]] = []
        raised: List[str] = []
        for alert in alerts:
            # 2026-10: one malformed alert (a non-string ``threat.cve`` or ``tags``) makes the
            # processor raise outside its query error handling; report it and keep the others'
            # responses instead of ending the demo with a traceback and no output.
            try:
                responses.append(processor.enrich_alert_read_only(alert).to_dict())
            except Exception as exc:  # noqa: BLE001 - reported per alert, not raised, for a presenter
                raised.append(f"{alert.get('alert_id')!r} ({type(exc).__name__}: {exc})")
        print(json.dumps(responses, indent=2, default=str))

        # 2026-10: a failed enrichment query leaves the processor's defaults (nothing found,
        # confidence 0.0) for every part not read yet, so the run must not end as a success. A rejected alert (no alert_id,
        # no indicator) has an empty enrichment and is the processor's normal answer to it.
        failed = [r["alert_id"] for r in responses if r["enrichment"] and "error" in r["query_metadata"]]
        if raised:
            _err(f"The processor raised on {len(raised)} alert(s), left out of the output: {'; '.join(raised)}")
        if failed:
            _err(
                f"An enrichment query failed for alert(s) {', '.join(map(repr, failed))}: the graph was not "
                "fully read (see query_metadata.error)"
            )
            return EXIT_NEO4J
        return EXIT_USAGE if raised else EXIT_OK
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
