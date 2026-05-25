#!/usr/bin/env python3
"""
Run the Cypher catalog over the Neo4j **HTTP Query API v2** and optionally
collect the results to disk.

Companion to tests/test_cypher_query_catalog.py. Use this when the Neo4j Bolt
port isn't reachable from where you are — e.g. a Cloudflare-proxied endpoint
that only speaks Bolt-over-WebSocket (the Neo4j Browser works, but the Python
Bolt driver, which needs raw Bolt-over-TCP, gets "looks like HTTP"). The HTTP
Query API is plain HTTPS, so it passes straight through Cloudflare.

It imports the SAME ``QUERY_CATALOG`` as the pytest harness (no duplication) and,
per query, (1) sends ``EXPLAIN <q>`` to check validity and (2) executes ``<q>``
and captures the returned rows.

With ``--out <dir>`` (or env ``CATALOG_OUTPUT_DIR``) it writes two artifacts to
that directory — meant for a deliverables folder like ``Sprint 2/``:
  * cypher_catalog_results.json — full machine-readable results (every row)
  * cypher_catalog_results.md   — readable report (summary + sample rows)
The runtime stays in the repo; only the collected DATA lands in <dir>.

Env:
  NEO4J_HTTP_URL   base URL (default: https://neo4j.edgeguard.org)
  NEO4J_DATABASE   database name (default: neo4j)
  NEO4J_USER       basic-auth user
  NEO4J_PASSWORD   basic-auth password
  CATALOG_OUTPUT_DIR  default output dir (overridden by --out)

Usage:
  set -a; source .env.edgeguard; set +a
  python scripts/run_cypher_catalog_http.py                       # print only
  python scripts/run_cypher_catalog_http.py --out "../Sprint 2"   # + write files
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tests"))

from test_cypher_query_catalog import QUERY_CATALOG  # noqa: E402

BASE = os.getenv("NEO4J_HTTP_URL", "https://neo4j.edgeguard.org").rstrip("/")
DB = os.getenv("NEO4J_DATABASE", "neo4j")
USER = os.getenv("NEO4J_USER", "neo4j")
PWD = os.getenv("NEO4J_PASSWORD", "")
URL = f"{BASE}/db/{DB}/query/v2"
_AUTH = "Basic " + base64.b64encode(f"{USER}:{PWD}".encode()).decode()
# Cloudflare fronts this endpoint and its bot rule 403s the default
# "Python-urllib/x.y" User-Agent (Error 1010). A normal browser UA passes.
_UA = os.getenv(
    "NEO4J_HTTP_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
)
_MD_SAMPLE_ROWS = 5  # rows shown per query in the .md report (full set is in the .json)


def _post(statement, params):
    """POST one Cypher statement to the Query API v2.

    Returns (fields, values, error_message). On success error_message is None.
    """
    body = json.dumps({"statement": statement, "parameters": params or {}}).encode()
    req = urllib.request.Request(URL, data=body, method="POST")
    req.add_header("Authorization", _AUTH)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", _UA)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode())
        errs = payload.get("errors") or []
        if errs:
            return None, None, errs[0].get("message") or str(errs[0])
        data = payload.get("data", {})
        return data.get("fields", []), data.get("values", []), None
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        try:
            msg = (json.loads(detail).get("errors") or [{}])[0].get("message") or detail
        except Exception:
            msg = detail
        return None, None, f"HTTP {e.code}: {msg[:200]}"
    except Exception as e:  # noqa: BLE001 — report mode, surface everything
        return None, None, f"{type(e).__name__}: {e}"


def _md_cell(v):
    s = json.dumps(v, default=str) if isinstance(v, (list, dict)) else str(v)
    s = s.replace("|", "\\|").replace("\n", " ")
    return s if len(s) <= 60 else s[:57] + "..."


def _write_outputs(out_dir, results, summary):
    os.makedirs(out_dir, exist_ok=True)
    meta = {
        "endpoint": URL,
        "user": USER,
        "database": DB,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **summary,
    }
    json_path = os.path.join(out_dir, "cypher_catalog_results.json")
    with open(json_path, "w") as f:
        json.dump({"meta": meta, "results": results}, f, indent=2, default=str)

    lines = [
        "# EdgeGuard — Cypher catalog results",
        "",
        f"- Endpoint: `{URL}` (db `{DB}`, user `{USER}`)",
        f"- Generated: {meta['generated_utc']}",
        f"- {summary['query_count']} queries — **{summary['valid']} valid**, "
        f"{summary['invalid']} invalid, {summary['empty']} valid-but-empty",
        "",
        "## Summary",
        "",
        "| id | layer | valid | rows | title |",
        "|----|-------|:-----:|-----:|-------|",
    ]
    for r in results:
        valid = "yes" if r["valid"] else "**NO**"
        rows = "" if r["row_count"] is None else r["row_count"]
        lines.append(f"| `{r['id']}` | {r['layer']} | {valid} | {rows} | {r['title']} |")

    lines += ["", "## Results with data", ""]
    for r in results:
        if not r["valid"] or not r["rows"]:
            continue
        lines += [f"### `{r['id']}` — {r['title']}", "", f"```cypher\n{r['cypher']}\n```", ""]
        fields = r["fields"]
        lines.append("| " + " | ".join(fields) + " |")
        lines.append("|" + "|".join(["---"] * len(fields)) + "|")
        for row in r["rows"][:_MD_SAMPLE_ROWS]:
            lines.append("| " + " | ".join(_md_cell(c) for c in row) + " |")
        if r["row_count"] > _MD_SAMPLE_ROWS:
            lines.append(f"\n_… {r['row_count'] - _MD_SAMPLE_ROWS} more rows in the JSON_")
        lines.append("")

    empty_ids = [r["id"] for r in results if r["valid"] and r["row_count"] == 0]
    invalid_ids = [r["id"] for r in results if not r["valid"]]
    lines += [
        "## Valid but empty (graph slice not populated)",
        "",
        ", ".join(f"`{i}`" for i in empty_ids) or "_none_",
        "",
    ]
    if invalid_ids:
        lines += ["## Invalid", "", ", ".join(f"`{i}`" for i in invalid_ids), ""]

    md_path = os.path.join(out_dir, "cypher_catalog_results.md")
    with open(md_path, "w") as f:
        f.write("\n".join(lines))
    return json_path, md_path


def main():
    args = sys.argv[1:]
    out_dir = args[args.index("--out") + 1] if "--out" in args else os.getenv("CATALOG_OUTPUT_DIR")

    print(f"HTTP Query API : {URL}")
    print(f"User           : {USER}")
    print(f"Queries        : {len(QUERY_CATALOG)}\n")
    print(f"{'id':34} {'layer':12} {'valid':5} {'rows':>6}  title")
    print("-" * 108)

    results = []
    n_valid = n_invalid = 0
    empties = []
    for q in QUERY_CATALOG:
        _, _, verr = _post("EXPLAIN " + q.cypher, q.params)
        rec = {
            "id": q.id,
            "layer": q.layer,
            "title": q.title,
            "cypher": q.cypher,
            "params": q.params,
            "valid": verr is None,
            "explain_error": verr,
            "fields": [],
            "row_count": None,
            "rows": [],
            "run_error": None,
        }
        if verr:
            n_invalid += 1
            results.append(rec)
            print(f"{q.id:34} {q.layer:12} {'FAIL':5} {'-':>6}  {q.title}\n{'':54}<<< {verr}")
            continue
        n_valid += 1
        fields, vals, rerr = _post(q.cypher, q.params)
        if rerr:
            rec["run_error"] = rerr
            nrows = -1
        else:
            rec["fields"], rec["rows"], rec["row_count"] = fields or [], vals or [], len(vals or [])
            nrows = rec["row_count"]
            if nrows == 0:
                empties.append(q.id)
        results.append(rec)
        print(f"{q.id:34} {q.layer:12} {('ERR' if nrows < 0 else 'OK'):5} {nrows:>6}  {q.title}")

    print("-" * 108)
    print(f"{len(QUERY_CATALOG)} queries — {n_valid} valid (EXPLAIN ok), {n_invalid} invalid")
    if empties:
        print(f"{len(empties)} valid-but-empty: {', '.join(empties)}")

    if out_dir:
        summary = {"query_count": len(results), "valid": n_valid, "invalid": n_invalid, "empty": len(empties)}
        jp, mp = _write_outputs(out_dir, results, summary)
        print(f"\nWrote results to:\n  {jp}\n  {mp}")


if __name__ == "__main__":
    main()
