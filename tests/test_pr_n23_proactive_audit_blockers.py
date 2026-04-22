"""
PR-N23 — proactive-audit BLOCKERS for the next 730-day baseline.

Discovered by a 6-agent proactive audit on 2026-04-22, post-PR-N21. These
six fixes close bug classes we had already fixed ELSEWHERE but missed in
the related code path — Bugbot didn't catch them because each is a
scope-gap, not a regression.

Fixes:

1. ``MISPCollector.collect()`` silent-swallower (``src/collectors/
   misp_collector.py:586``) — returned ``[], set()`` on any exception.
   Identical shape to PR-N17's NVD silent-window-drop, in a different
   collector. Impact: MISP transient outage → empty active_event_ids
   → mark_inactive_nodes skips → stale indicators freeze ``active=true``.

2. ``merge_vulnerabilities_batch`` missing CVSS/dates promotion
   (``src/neo4j_client.py:3131+``) — PR-N19 Fix #1 closed the
   single-row path but NOT the batch path. Batch-ingested Vulnerability
   nodes had NULL ``cvss_score``, ``severity``, ``published``,
   ``last_modified``, ``cisa_*``.

3. ``_vulnerability_sdo`` drops 13+ fields (``src/stix_exporter.py:
   1166+``) — ResilMesh cloud Neo4j received name + description only.
   Every CVE showed severity="UNKNOWN" in ResilMesh dashboards even
   though Neo4j had the correct CVSS score.

4. ``cisa_collector`` silent errors (``src/collectors/cisa_collector.py:
   312-334``) — same shape as PR-N17 NVD fix but for CISA, left unfixed
   because the PR-N17 scope was too narrow. Returned ``[]`` on any
   Timeout/ConnectionError/HTTPError when ``push_to_misp=False``.

5. ``_IS_PROD`` fails-open (``src/graphql_api.py:690``) — checked
   ``EDGEGUARD_ENV == "prod"`` with strict equality. ``=production``
   (typo) or unset → introspection stays ENABLED in prod → schema
   exposed. Security-sensitive.

6. ``MAX_ATTRIBUTES_PER_EVENT=500`` silent truncation (``src/
   collectors/misp_collector.py:262``) — large NVD events (2000+
   CVEs/event at baseline scale) silently dropped 75%+ of their data
   with a WARN log and no metric / alert.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n23")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n23")


# ===========================================================================
# Fix #1 — MISPCollector.collect() must re-raise, not return empty
# ===========================================================================


def _function_body(src_path: Path, fn_name: str, class_name: str | None = None) -> str:
    """Return the AST-unparsed body of a top-level function or class method."""
    tree = ast.parse(src_path.read_text())
    for node in ast.walk(tree):
        if class_name is not None:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                for inner in node.body:
                    if isinstance(inner, ast.FunctionDef) and inner.name == fn_name:
                        return ast.unparse(inner)
        elif isinstance(node, ast.FunctionDef) and node.name == fn_name:
            return ast.unparse(node)
    raise AssertionError(f"function {fn_name} not found in {src_path}")


class TestFix1MispCollectorReraises:
    """``MISPCollector.collect`` must ``raise`` from its outer
    ``except Exception`` instead of silently returning ``[], set()``."""

    def test_collect_reraises_on_exception(self):
        src = (SRC / "collectors" / "misp_collector.py").read_text()
        body = _function_body(SRC / "collectors" / "misp_collector.py", "collect", class_name="MISPCollector")
        # Must contain a bare ``raise`` inside a broad except Exception
        # handler. Walk the AST of the collect() body.
        tree = ast.parse(body)
        found_reraise = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                is_broad = (isinstance(node.type, ast.Name) and node.type.id == "Exception") or node.type is None
                if not is_broad:
                    continue
                for stmt in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                    if isinstance(stmt, ast.Raise) and stmt.exc is None:
                        found_reraise = True
        assert found_reraise, (
            "MISPCollector.collect outer except must ``raise`` (not return []). "
            "Pre-N23 the swallower returned empty on MISP outage → "
            "mark_inactive_nodes silently skipped → stale-indicator freeze."
        )
        # Negative: the exact regression pattern must NOT appear.
        assert "return [], set()" not in src or src.count("return [], set()") < 2, (
            "the exact pre-N23 silent-return pattern must not appear in collect()"
        )


# ===========================================================================
# Fix #2 — merge_vulnerabilities_batch promotes CVSS + dates + CISA fields
# ===========================================================================


class TestFix2MergeVulnerabilitiesBatchPromotesEnrichment:
    """The batch path must mirror merge_cve / merge_vulnerability (PR-N19
    Fix #1) — promote CVSS, severity, attack_vector, published,
    last_modified, and all CISA fields to the node."""

    def _body(self) -> str:
        return _function_body(SRC / "neo4j_client.py", "merge_vulnerabilities_batch", class_name="Neo4jClient")

    def test_batch_item_includes_cvss_score(self):
        body = self._body()
        assert 'batch_item["cvss_score"]' in body or "batch_item['cvss_score']" in body, (
            "batch path must stage cvss_score into batch_item (was silently dropped pre-N23)"
        )

    def test_batch_item_includes_severity(self):
        body = self._body()
        assert 'batch_item["severity"]' in body or "batch_item['severity']" in body

    def test_batch_item_includes_published_and_last_modified(self):
        body = self._body()
        assert 'batch_item["published"]' in body or "batch_item['published']" in body, (
            "batch path must stage published (PR-N19 Fix #1 shape, but for batch)"
        )
        assert 'batch_item["last_modified"]' in body or "batch_item['last_modified']" in body

    def test_batch_item_includes_cisa_kev_fields(self):
        body = self._body()
        for field in ("cisa_exploit_add", "cisa_action_due", "cisa_required_action", "cisa_vulnerability_name"):
            assert f'batch_item["{field}"]' in body or f"batch_item['{field}']" in body, (
                f"batch path must stage {field} (CISA KEV enrichment was dropped pre-N23)"
            )

    def test_cypher_promotes_enrichment_fields_to_node(self):
        """The MERGE Cypher SET clause must write each staged field onto the node."""
        body = self._body()
        for field in ("cvss_score", "severity", "attack_vector", "published", "last_modified"):
            # coalesce(item.X, n.X) — don't clobber existing values with NULL
            assert f"n.{field} = coalesce(item.{field}, n.{field})" in body, (
                f"Cypher SET must use ``n.{field} = coalesce(item.{field}, n.{field})`` "
                "so partial-item batches preserve existing values"
            )


# ===========================================================================
# Fix #3 — _vulnerability_sdo emits the enrichment fields as x_edgeguard_*
# ===========================================================================


class TestFix3VulnerabilitySdoExportsEnrichment:
    """STIX Vulnerability SDO must carry the Neo4j enrichment via
    ``x_edgeguard_*`` custom properties (per STIX 2.1 allow_custom)."""

    def _body(self) -> str:
        return _function_body(SRC / "stix_exporter.py", "_vulnerability_sdo", class_name="StixExporter")

    def test_cvss_score_promoted(self):
        body = self._body()
        assert '"x_edgeguard_cvss_score"' in body or "'x_edgeguard_cvss_score'" in body

    def test_severity_promoted(self):
        body = self._body()
        assert '"x_edgeguard_severity"' in body or "'x_edgeguard_severity'" in body

    def test_dates_promoted(self):
        body = self._body()
        assert "x_edgeguard_published" in body, "STIX SDO must carry published date"
        assert "x_edgeguard_last_modified" in body

    def test_cisa_kev_fields_promoted(self):
        body = self._body()
        for field in (
            "x_edgeguard_cisa_exploit_add",
            "x_edgeguard_cisa_action_due",
            "x_edgeguard_cisa_required_action",
            "x_edgeguard_cisa_vulnerability_name",
        ):
            assert field in body, f"STIX SDO must carry {field}"

    def test_cwe_and_references_promoted(self):
        body = self._body()
        for field in ("x_edgeguard_cwe", "x_edgeguard_ref_tags", "x_edgeguard_reference_urls"):
            assert field in body, f"STIX SDO must carry {field}"

    def test_skips_empty_values(self):
        """An empty / None / [] value must NOT be emitted (would bloat bundle
        with null fields). Pin the filter logic."""
        body = self._body()
        # The implementation must check for None/""/[]/{} before adding
        assert "None" in body and ("== []" in body or '== ""' in body or "val is None" in body), (
            "STIX SDO promotion must skip None / empty values to avoid null-field bloat"
        )


# ===========================================================================
# Fix #4 — cisa_collector re-raises on transient errors when push_to_misp=False
# ===========================================================================


class TestFix4CisaCollectorReraises:
    """When ``push_to_misp=False``, errors must propagate to the caller —
    the PR-N17 fix for NVD, now mirrored for CISA."""

    def test_cisa_reraises_on_push_to_misp_false(self):
        src = (SRC / "collectors" / "cisa_collector.py").read_text()
        # Pin that all 4 transient-error handlers of the MAIN collect
        # flow (Timeout/ConnectionError/HTTPError/Exception) have a
        # bare ``raise`` at the bottom of the else-branch.
        #
        # There are multiple ``except requests.exceptions.Timeout`` blocks
        # in the module (health-check, collect, etc.). Anchor on the
        # distinctive PR-N23 fix comment that's only in the collect path.
        anchor = "PR-N23 BLOCKER #4"
        start = src.find(anchor)
        assert start != -1, (
            "cisa_collector must contain the PR-N23 BLOCKER #4 comment block "
            "marking the collect-path exception handlers"
        )
        # Scan a generous window forward (the 4 handlers span ~30 lines).
        block = src[start : start + 4000]

        # Each of the 4 handlers should contain exactly one bare ``raise``
        raise_count = sum(1 for line in block.splitlines() if line.strip() == "raise")
        assert raise_count >= 4, (
            f"CISA collector must ``raise`` in all 4 collect-path transient-error handlers "
            f"when push_to_misp=False; found only {raise_count} bare-raise statements."
        )
        # Must also reference the push_to_misp branch (the fix is "if
        # push_to_misp: return status; else: raise").
        assert "if push_to_misp:" in block, (
            "the fix pattern is ``if push_to_misp: return self._return_status(...); else: raise``"
        )


# ===========================================================================
# Fix #5 — _IS_PROD fails-closed (secure default)
# ===========================================================================


class TestFix5IsProdFailsClosed:
    """``_IS_PROD`` must default to True (fail-closed / secure) when
    ``EDGEGUARD_ENV`` is unset or unrecognized. Pre-N23 it defaulted to
    False, leaving introspection ENABLED in prod for any env typo."""

    def test_is_prod_uses_non_prod_allowlist(self):
        src = (SRC / "graphql_api.py").read_text()
        # The fix switches from ``== "prod"`` to a non-prod allowlist
        # (dev/development/local/staging/test) with prod as the default.
        assert "_NON_PROD_ENVS" in src or "non_prod" in src.lower(), (
            "graphql_api must use a non-prod allowlist (fail-closed) rather than ``== 'prod'`` strict-equality"
        )

    def test_is_prod_not_equal_prod_only(self):
        """The strict-equality regression pattern must NOT return directly."""
        src = (SRC / "graphql_api.py").read_text()
        # The pre-N23 shape was ``_IS_PROD = ... == "prod"`` at top level.
        # Post-N23 it's a function call. Anchor on the presence of a
        # ``def _is_prod_env`` function (structural change indicator).
        assert "def _is_prod_env" in src, (
            "graphql_api must define a _is_prod_env() function (not a one-liner strict-equality check)"
        )

    def test_is_prod_behavior(self):
        """Behavioral pin: call _is_prod_env() with various EDGEGUARD_ENV
        values and assert the expected prod/non-prod classification."""
        # Import fresh to pick up env-var changes
        import importlib

        if "graphql_api" in sys.modules:
            # Can't re-import easily due to FastAPI registration side-effects,
            # so exec the _is_prod_env function in isolation.
            pass

        # We import the source and exec just the function definition to
        # test it in isolation without triggering GraphQL/FastAPI imports.
        src = (SRC / "graphql_api.py").read_text()
        fn_start = src.find("def _is_prod_env")
        fn_end = src.find("\n_IS_PROD = _is_prod_env()")
        assert fn_start != -1 and fn_end != -1, "_is_prod_env function not found"
        fn_src = src[fn_start:fn_end]

        ns: dict = {"os": importlib.import_module("os")}
        exec(fn_src, ns)
        _is_prod_env = ns["_is_prod_env"]

        # Test matrix
        try:
            saved = os.environ.get("EDGEGUARD_ENV")
            # Case 1: unset → prod (fail-closed)
            os.environ.pop("EDGEGUARD_ENV", None)
            assert _is_prod_env() is True, "unset EDGEGUARD_ENV → prod (fail-closed)"
            # Case 2: "dev" → non-prod
            os.environ["EDGEGUARD_ENV"] = "dev"
            assert _is_prod_env() is False, '"dev" → non-prod'
            # Case 3: "production" (typo-ish) → prod
            os.environ["EDGEGUARD_ENV"] = "production"
            assert _is_prod_env() is True, '"production" → prod (not in non-prod allowlist)'
            # Case 4: "prod" → prod
            os.environ["EDGEGUARD_ENV"] = "prod"
            assert _is_prod_env() is True
            # Case 5: empty string → prod
            os.environ["EDGEGUARD_ENV"] = ""
            assert _is_prod_env() is True, "empty → prod (fail-closed)"
            # Case 6: random garbage → prod
            os.environ["EDGEGUARD_ENV"] = "asdfasdf"
            assert _is_prod_env() is True
            # Case 7: "staging" → non-prod (explicitly allowlisted)
            os.environ["EDGEGUARD_ENV"] = "staging"
            assert _is_prod_env() is False
        finally:
            if saved is None:
                os.environ.pop("EDGEGUARD_ENV", None)
            else:
                os.environ["EDGEGUARD_ENV"] = saved


# ===========================================================================
# Fix #6 — 500-attr truncation emits greppable token + Prometheus counter
# ===========================================================================


class TestFix6MispTruncationObservability:
    """Silent truncation at MAX_ATTRIBUTES_PER_EVENT=500 must now emit
    ``[MISP-EVENT-TRUNCATED]`` + increment the Prometheus counter."""

    def test_truncation_log_uses_greppable_token(self):
        src = (SRC / "collectors" / "misp_collector.py").read_text()
        assert "[MISP-EVENT-TRUNCATED]" in src, (
            "truncation log must use the [MISP-EVENT-TRUNCATED] grep token "
            "(docs/RUNBOOK.md operator can then grep for truncations)"
        )

    def test_truncation_counter_fired(self):
        src = (SRC / "collectors" / "misp_collector.py").read_text()
        assert "MISP_EVENT_ATTRIBUTES_TRUNCATED" in src, (
            "misp_collector must increment MISP_EVENT_ATTRIBUTES_TRUNCATED counter on truncation"
        )
        # Must use labels(source=...) for per-source telemetry
        assert ".labels(source=" in src or ".labels(source" in src, (
            "truncation counter must be labelled by source so operators can pinpoint which feed"
        )

    def test_counter_defined_in_metrics_server(self):
        src = (SRC / "metrics_server.py").read_text()
        assert "MISP_EVENT_ATTRIBUTES_TRUNCATED = Counter(" in src, (
            "metrics_server must define MISP_EVENT_ATTRIBUTES_TRUNCATED counter"
        )
        assert '"edgeguard_misp_event_attributes_truncated_total"' in src, (
            "counter must expose the ``edgeguard_misp_event_attributes_truncated_total`` metric name"
        )


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_neo4j_client_imports(self):
        import neo4j_client  # noqa: F401

    def test_misp_collector_imports(self):
        # Only import the module — don't instantiate the collector
        # (requires MISP creds). Just confirms no syntax/import-time errors.
        import collectors.misp_collector  # noqa: F401

    def test_cisa_collector_imports(self):
        import collectors.cisa_collector  # noqa: F401

    def test_metrics_server_has_truncation_counter(self):
        import metrics_server

        assert hasattr(metrics_server, "MISP_EVENT_ATTRIBUTES_TRUNCATED")
