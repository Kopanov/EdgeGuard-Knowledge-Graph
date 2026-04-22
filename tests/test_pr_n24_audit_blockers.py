"""
PR-N24 — proactive 7-agent audit BLOCKERs/HIGHs.

After PR-N20/N21/N22/N23 (15 rounds of reactive Bugbot fixes), a 7-agent
proactive audit on 2026-04-22 surfaced 6 additional blockers / highs that
the reactive loop missed. PR-N24 closes them before the next 730-day
baseline run.

Fixes tracked here:

* **B1** — ``docs/RUNBOOK.md`` referenced ``python -m src.build_relationships
  --step <N>`` for APOC partial-batch recovery, but no such CLI flag
  exists. Operator on 3am pager call would chase a phantom flag for
  20 minutes. Fix: replace the line with the real Airflow-UI re-trigger
  path + an Issue #58 cross-ref.

* **B2** — ``prometheus/alertmanager.yml`` shipped with
  ``service_key: '<YOUR_PAGERDUTY_KEY>'``. PagerDuty silently 403s on
  every page during the 26h baseline window. Fix: env-var template
  + a NEW preflight check ([7b]) that refuses to launch when any
  placeholder shape is still in the file.

* **B3.1 / B3.2** — OTX + MITRE collectors had the same silent-swallower
  shape PR-N17 fixed in NVD and PR-N23 fixed in CISA: their broad
  exception handlers returned a status dict (or empty list) on
  ``push_to_misp=False`` instead of re-raising. Fix: ``if push_to_misp:
  return self._return_status(...); raise``.

* **B3.3** — AST-scan CI test forbidding the silent-swallower shape across
  ``src/collectors/`` so the next collector added doesn't reintroduce
  the bug class. Defensive — the explicit per-collector pins above
  will fail before this scan does, but the scan catches future
  regressions in collectors not pinned by name.

* **H1** — ``_is_prod_env`` was duplicated in ``src/graphql_api.py`` and
  inverted (fails-open) in ``src/query_api.py``: a typo'd
  ``EDGEGUARD_ENV`` would lock GraphQL but skip the API-key gate. PR-N24
  centralizes the helper as ``src/config.is_production_env()`` and
  rewires both API modules to import it. Single source of truth →
  no split state.

* **H2** — ``baseline_postcheck_task`` had ``trigger_rule=ALL_SUCCESS``,
  meaning the post-baseline INV-2 / INV-3 invariant probes did NOT run
  if any upstream enrichment task failed — exactly when operators most
  need diagnostic counts. Fix: flip to ``NONE_FAILED_MIN_ONE_SUCCESS``
  so the diagnostics always run when at least one upstream succeeded.

* **H3** — ``edgeguard_misp_event_attributes_truncated_total`` counter
  was added in PR-N23 but no alert wired it. Counter without alert =
  unobservable counter. Fix: add ``EdgeGuardMispEventAttributesTruncated``
  to ``prometheus/alerts.yml`` and bump the preflight ``ALERT_COUNT``
  floor from ≥ 8 to ≥ 9.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
DOCS = REPO_ROOT / "docs"
SCRIPTS = REPO_ROOT / "scripts"
PROMETHEUS = REPO_ROOT / "prometheus"
DAGS = REPO_ROOT / "dags"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n24")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n24")


# ===========================================================================
# Helpers
# ===========================================================================


def _function_node(src_path: Path, fn_name: str, class_name: str | None = None) -> ast.FunctionDef:
    """Locate a function/method node by name + optional class."""
    tree = ast.parse(src_path.read_text())
    for node in ast.walk(tree):
        if class_name is not None:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                for inner in node.body:
                    if isinstance(inner, ast.FunctionDef) and inner.name == fn_name:
                        return inner
        elif isinstance(node, ast.FunctionDef) and node.name == fn_name:
            return node
    raise AssertionError(f"function {fn_name} not found in {src_path}")


def _is_broad_handler(node: ast.ExceptHandler) -> bool:
    """``except Exception``, ``except`` (bare), or ``except BaseException``."""
    if node.type is None:
        return True
    if isinstance(node.type, ast.Name):
        return node.type.id in {"Exception", "BaseException"}
    return False


def _has_bare_raise(node: ast.ExceptHandler) -> bool:
    """At least one ``raise`` (bare or non-bare) anywhere in the handler body."""
    for stmt in ast.walk(ast.Module(body=node.body, type_ignores=[])):
        if isinstance(stmt, ast.Raise):
            return True
    return False


# ===========================================================================
# Fix B1 — RUNBOOK no longer references the phantom --step N CLI flag
# ===========================================================================


class TestB1RunbookNoPhantomStepFlag:
    """``docs/RUNBOOK.md`` must not promise a ``--step <N>`` CLI flag for
    ``build_relationships`` because no such flag exists."""

    def test_runbook_does_not_reference_step_n_cli_flag(self):
        text = (DOCS / "RUNBOOK.md").read_text()
        # Pre-N24: "invoke ``python -m src.build_relationships --step <N>``"
        # was the operator instruction. No such CLI exists.
        assert "build_relationships --step" not in text, (
            "RUNBOOK must not reference ``build_relationships --step <N>`` — "
            "the CLI flag does not exist (Issue #58). At 3am the operator "
            "would chase a phantom flag for 20 minutes."
        )

    def test_runbook_points_to_airflow_ui_recovery(self):
        text = (DOCS / "RUNBOOK.md").read_text()
        # The fix replaces the phantom flag with the real Airflow-UI path.
        assert "Airflow UI" in text, (
            "RUNBOOK must reference ``Airflow UI`` for the APOC partial-batch "
            "recovery path (the actual operator action)"
        )

    def test_runbook_cross_refs_step_n_issue(self):
        text = (DOCS / "RUNBOOK.md").read_text()
        # The fix should reference the tracking issue for adding the flag.
        assert "Issue #58" in text or "issue #58" in text, (
            "RUNBOOK should cross-ref Issue #58 (tracking the missing --step N flag)"
        )


# ===========================================================================
# Fix B2 — alertmanager pager wiring not still placeholder + preflight gate
# ===========================================================================


class TestB2AlertmanagerNoPlaceholderPagerKey:
    """``prometheus/alertmanager.yml`` must not ship with a literal pager
    placeholder, and the preflight script must refuse to launch when one
    is found."""

    def test_alertmanager_has_no_placeholder_pager_key(self):
        """Scan uncommented YAML content only. The explanatory comment in
        the file documents the placeholder's history — matching the
        placeholder inside a ``#`` comment would fail-close on docs,
        not on real config."""
        path = PROMETHEUS / "alertmanager.yml"
        lines = path.read_text().splitlines()
        # Strip each line's trailing ``#...`` portion before scanning.
        uncommented = "\n".join(line.split("#", 1)[0] for line in lines)
        # The placeholder is dangerous only when it's a YAML scalar value
        # (single- or double-quoted). Match only those shapes.
        forbidden = re.compile(
            r"""['"]<YOUR_PAGERDUTY_KEY>['"]|"""
            r"""['"]<YOUR_API_KEY>['"]|"""
            r"""['"]<PLACEHOLDER>['"]|"""
            r"""['"]XXXXXXXX-XXXX['"]"""
        )
        assert not forbidden.search(uncommented), (
            "alertmanager.yml still ships with a placeholder pager key as a YAML value — "
            "PagerDuty will silently 403 every alert during the 26h baseline. "
            "Replace with EDGEGUARD_PAGERDUTY_INTEGRATION_KEY env-var substitution."
        )

    def test_alertmanager_uses_env_var_substitution(self):
        text = (PROMETHEUS / "alertmanager.yml").read_text()
        assert "${EDGEGUARD_PAGERDUTY_INTEGRATION_KEY}" in text, (
            "alertmanager.yml service_key must use ``${EDGEGUARD_PAGERDUTY_INTEGRATION_KEY}`` "
            "env-var template so operators can wire a real key without editing the file"
        )

    def test_preflight_check_7b_present(self):
        text = (SCRIPTS / "preflight_baseline.sh").read_text()
        assert "PR-N24 BLOCKER B2" in text, (
            "preflight_baseline.sh must contain the [7b] PR-N24 B2 alertmanager "
            "placeholder check that refuses to launch with placeholders in place"
        )
        # The fail message must reference the placeholder shapes.
        assert "<YOUR_PAGERDUTY_KEY>" in text, "preflight check [7b] must scan for the <YOUR_PAGERDUTY_KEY> placeholder"

    def test_preflight_alert_count_floor_bumped(self):
        """PR-N24 H3 added EdgeGuardMispEventAttributesTruncated, so the
        preflight defense-in-depth alert-count floor must be ≥ 9."""
        text = (SCRIPTS / "preflight_baseline.sh").read_text()
        # Pre-N24 H3 the floor was 8; post-N24 H3 it must be 9+.
        assert "ALERT_COUNT" in text and "-ge 9" in text, (
            "preflight ALERT_COUNT floor must be ``-ge 9`` after PR-N24 H3 added EdgeGuardMispEventAttributesTruncated"
        )


# ===========================================================================
# Fix B3.1 — OTX collector re-raises on push_to_misp=False
# ===========================================================================


class TestB3OtxCollectorReraises:
    """All 4 transient-error handlers in ``OTXCollector.collect`` must
    re-raise when ``push_to_misp=False`` instead of returning a status
    dict that the caller can't distinguish from an empty success."""

    def test_otx_collect_handlers_have_bare_raise(self):
        src = (SRC / "collectors" / "otx_collector.py").read_text()
        # Anchor on the PR-N24 BLOCKER B3 comment so we scan only the
        # collect() handlers, not the unrelated health-check ones.
        anchor = "PR-N24 BLOCKER B3"
        start = src.find(anchor)
        assert start != -1, (
            "otx_collector.py must contain the PR-N24 BLOCKER B3 comment "
            "block above the collect-path exception handlers"
        )
        block = src[start : start + 4000]
        bare_raise_count = sum(1 for line in block.splitlines() if line.strip() == "raise")
        assert bare_raise_count >= 4, (
            "OTX collector must contain a bare ``raise`` in each of the 4 "
            "collect-path handlers (Timeout/ConnectionError/HTTPError/Exception); "
            f"found only {bare_raise_count}."
        )
        assert "if push_to_misp:" in block, "fix shape is ``if push_to_misp: return self._return_status(...); raise``"


# ===========================================================================
# Fix B3.2 — MITRE collector re-raises on push_to_misp=False
# ===========================================================================


class TestB3MitreCollectorReraises:
    """``MitreCollector.collect``'s broad ``except Exception`` must re-raise
    when ``push_to_misp=False`` instead of returning ``[]`` (which the
    caller can't tell apart from "MITRE has no updates today")."""

    def test_mitre_collect_handler_reraises(self):
        src = (SRC / "collectors" / "mitre_collector.py").read_text()
        anchor = "PR-N24 BLOCKER B3"
        start = src.find(anchor)
        assert start != -1, (
            "mitre_collector.py must contain the PR-N24 BLOCKER B3 comment "
            "block above the collect-path exception handler"
        )
        block = src[start : start + 1500]

        # Strip comment content so ``# ... else []`` documentation doesn't
        # trigger the negative pin — we want to match real code only.
        code_only = "\n".join(line.split("#", 1)[0] for line in block.splitlines())

        # The pre-N24 silent-list pattern must NOT remain in actual code.
        assert "else []" not in code_only, (
            "mitre_collector must not return ``[]`` on the push_to_misp=False "
            "branch — that's the silent-swallower shape PR-N24 closes."
        )
        # Must explicitly re-raise after the push_to_misp=True branch.
        after_gate = code_only.split("if push_to_misp:")[-1]
        assert "raise" in after_gate, "mitre_collector must ``raise`` after the ``if push_to_misp: return ...`` branch"


# ===========================================================================
# Fix B3.3 — AST scan: forbid the silent-swallower pattern across collectors
# ===========================================================================


class TestB3AstScanNoSilentSwallowers:
    """Cross-collector AST scan: any ``collect`` method (or any function
    that takes a ``push_to_misp`` parameter) with a broad exception
    handler MUST re-raise inside that handler — no silent fallback.

    Defensive scan to prevent the bug class returning when a NEW collector
    is added without remembering the per-collector pin."""

    # Some collectors are wrappers / utility modules; collect-method scans
    # don't apply.
    _COLLECTOR_FILES = sorted(
        p
        for p in (SRC / "collectors").glob("*.py")
        if p.name not in {"__init__.py", "collector_utils.py", "misp_writer.py"}
    )

    # PR-N24 scope decision: the AST scan found the same silent-swallower
    # bug class in several collectors beyond the four PR-N24 closes
    # (MISP/CISA/OTX/MITRE/NVD). Rather than balloon PR-N24 into a
    # full bug-class sweep across every collector, these are tracked as
    # follow-up in Issue #68 and will ship in PR-N25.
    #
    # The AST scan still enforces the invariant going forward — any NEW
    # collector added with this pattern will fail the scan. The set below
    # is a temporary MAX — it must shrink, never grow. PR-N25 removes
    # entries as each collector is fixed. When empty, the allowlist
    # short-circuit can be deleted entirely.
    _KNOWN_OFFENDERS_BACKLOG = frozenset(
        {
            "finance_feed_collector.py",
            "global_feed_collector.py",
            "vt_collector.py",
        }
    )

    def _broad_handlers_in_function(self, fn: ast.FunctionDef) -> list[ast.ExceptHandler]:
        broad: list[ast.ExceptHandler] = []
        for node in ast.walk(fn):
            if isinstance(node, ast.ExceptHandler) and _is_broad_handler(node):
                broad.append(node)
        return broad

    def _functions_with_push_to_misp_param(self, tree: ast.Module) -> list[ast.FunctionDef]:
        out: list[ast.FunctionDef] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                arg_names = {a.arg for a in node.args.args} | {a.arg for a in node.args.kwonlyargs}
                if "push_to_misp" in arg_names:
                    out.append(node)
        return out

    def test_no_collector_collect_method_silently_swallows(self):
        """Every function in ``src/collectors/`` that takes ``push_to_misp``
        must, in any broad ``except Exception`` handler, contain at least
        one ``raise`` — not silently fall back to a status dict / list.

        Collectors in ``_KNOWN_OFFENDERS_BACKLOG`` are exempt (tracked in
        Issue #68, PR-N25 follow-up). The allowlist must shrink, never grow."""
        offenders: list[str] = []
        for path in self._COLLECTOR_FILES:
            if path.name in self._KNOWN_OFFENDERS_BACKLOG:
                continue
            tree = ast.parse(path.read_text())
            for fn in self._functions_with_push_to_misp_param(tree):
                for handler in self._broad_handlers_in_function(fn):
                    if not _has_bare_raise(handler):
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}:{handler.lineno} "
                            f"in function ``{fn.name}`` — broad except has no ``raise``"
                        )
        assert not offenders, (
            "the following collector exception handlers silently swallow errors "
            "(no ``raise`` in any broad ``except`` body of a ``push_to_misp``-aware "
            "function) — this is the PR-N17 / PR-N23 / PR-N24 bug class:\n  "
            + "\n  ".join(offenders)
            + "\n\nFix: ``if push_to_misp: return self._return_status(...); raise``"
        )

    def test_known_offenders_allowlist_shrinks_over_time(self):
        """Meta-pin: the PR-N25 follow-up allowlist must match only files
        that still have the bug. Once a collector is fixed in PR-N25,
        its entry must come out of ``_KNOWN_OFFENDERS_BACKLOG`` — the
        scan re-enables on fixed files. Prevents the allowlist from
        becoming a forever-silent escape hatch."""
        for collector_name in self._KNOWN_OFFENDERS_BACKLOG:
            path = SRC / "collectors" / collector_name
            assert path.exists(), (
                f"allowlist entry ``{collector_name}`` refers to a nonexistent file. "
                "Either remove the entry or point it at the correct path."
            )
            tree = ast.parse(path.read_text())
            still_broken = False
            for fn in self._functions_with_push_to_misp_param(tree):
                for handler in self._broad_handlers_in_function(fn):
                    if not _has_bare_raise(handler):
                        still_broken = True
                        break
                if still_broken:
                    break
            assert still_broken, (
                f"allowlist entry ``{collector_name}`` no longer has the "
                "silent-swallower bug — REMOVE it from _KNOWN_OFFENDERS_BACKLOG "
                "so the AST scan can enforce the invariant on this file going forward."
            )

    def test_no_return_empty_tuple_pattern(self):
        """The exact PR-N23 NVD-shape regression — ``return [], set()`` from
        a broad exception handler — must not appear in any collector."""
        offenders: list[str] = []
        for path in self._COLLECTOR_FILES:
            tree = ast.parse(path.read_text())
            for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
                if not _is_broad_handler(handler):
                    continue
                for stmt in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
                    if not isinstance(stmt, ast.Return):
                        continue
                    val = stmt.value
                    # ``return [], set()`` parses as Return(Tuple([List([]), Call(Name('set'))]))
                    if isinstance(val, ast.Tuple) and len(val.elts) == 2:
                        first, second = val.elts
                        if (
                            isinstance(first, ast.List)
                            and not first.elts
                            and isinstance(second, ast.Call)
                            and isinstance(second.func, ast.Name)
                            and second.func.id == "set"
                            and not second.args
                        ):
                            offenders.append(
                                f"{path.relative_to(REPO_ROOT)}:{stmt.lineno} — "
                                "``return [], set()`` from broad-except handler"
                            )
        assert not offenders, (
            "found the exact PR-N23 silent-swallower regression pattern "
            "(``return [], set()`` from ``except Exception``):\n  " + "\n  ".join(offenders)
        )


# ===========================================================================
# Fix H1 — is_production_env() centralized in src/config.py
# ===========================================================================


class TestH1IsProductionEnvCentralized:
    """``is_production_env()`` must live in ``src/config.py`` (single source
    of truth), and both API modules must import it instead of defining
    their own copy."""

    def test_config_defines_is_production_env(self):
        src = (SRC / "config.py").read_text()
        assert "def is_production_env" in src, (
            "src/config.py must define ``is_production_env()`` as the canonical project-wide prod-detection helper"
        )
        # Must include the fail-closed allowlist semantics.
        assert "_NON_PROD_ENVS" in src or "non_prod" in src.lower(), (
            "is_production_env() must use a non-prod allowlist (fail-closed)"
        )
        assert "IS_PROD" in src, "src/config.py should also expose the eagerly-evaluated ``IS_PROD`` constant"

    def test_graphql_api_imports_from_config(self):
        src = (SRC / "graphql_api.py").read_text()
        assert "from config import is_production_env" in src, (
            "graphql_api.py must import is_production_env from src.config (canonical helper). "
            "Pre-N24 it defined its own copy → split prod-detection state."
        )
        # The local function definition must be GONE.
        assert "def _is_prod_env" not in src, (
            "graphql_api.py must NOT redefine _is_prod_env — import from config instead"
        )

    def test_query_api_imports_from_config(self):
        src = (SRC / "query_api.py").read_text()
        assert "from config import is_production_env" in src, (
            "query_api.py must import is_production_env from src.config (canonical helper)"
        )
        # Strip comment lines so the PR-N24 audit-explanation block (which
        # quotes the pre-fix pattern verbatim in a ``#`` comment) doesn't
        # trigger the negative pin.
        code_only = "\n".join(line.split("#", 1)[0] for line in src.splitlines())
        # The pre-N24 fails-open shape must be gone from actual code.
        assert '_ENV = os.getenv("EDGEGUARD_ENV", "dev")' not in code_only, (
            "query_api.py must NOT use the fails-open ``EDGEGUARD_ENV, 'dev'`` default — "
            "use is_production_env() (fail-closed allowlist)"
        )

    def test_is_production_env_behavior(self):
        """Behavioural pin on the canonical helper: matrix of EDGEGUARD_ENV
        values → expected prod/non-prod classification. Fail-closed default."""
        # Exec the function definition in isolation to avoid full src/config.py
        # import side effects.
        src = (SRC / "config.py").read_text()
        fn_start = src.find("def is_production_env")
        assert fn_start != -1
        # Find the end: next top-level statement (line starting in column 0
        # that isn't part of the function or its decorators/blank lines).
        # Cheap heuristic: stop at the next ``IS_PROD = `` line.
        fn_end = src.find("IS_PROD = is_production_env()", fn_start)
        assert fn_end != -1, "expected ``IS_PROD = is_production_env()`` constant after the function"
        fn_src = src[fn_start:fn_end]

        ns: dict = {"os": __import__("os")}
        exec(fn_src, ns)
        is_prod = ns["is_production_env"]

        saved = os.environ.get("EDGEGUARD_ENV")
        try:
            os.environ.pop("EDGEGUARD_ENV", None)
            assert is_prod() is True, "unset → prod (fail-closed)"
            os.environ["EDGEGUARD_ENV"] = ""
            assert is_prod() is True, "empty → prod (fail-closed)"
            os.environ["EDGEGUARD_ENV"] = "dev"
            assert is_prod() is False
            os.environ["EDGEGUARD_ENV"] = "development"
            assert is_prod() is False
            os.environ["EDGEGUARD_ENV"] = "local"
            assert is_prod() is False
            os.environ["EDGEGUARD_ENV"] = "staging"
            assert is_prod() is False
            os.environ["EDGEGUARD_ENV"] = "test"
            assert is_prod() is False
            os.environ["EDGEGUARD_ENV"] = "prod"
            assert is_prod() is True
            os.environ["EDGEGUARD_ENV"] = "production"
            assert is_prod() is True, "production typo → prod (not in non-prod allowlist)"
            os.environ["EDGEGUARD_ENV"] = "asdfasdf"
            assert is_prod() is True, "garbage → prod (fail-closed)"
            # Whitespace + case insensitivity
            os.environ["EDGEGUARD_ENV"] = "  DEV  "
            assert is_prod() is False, "whitespace-padded ``DEV`` should normalize to dev"
        finally:
            if saved is None:
                os.environ.pop("EDGEGUARD_ENV", None)
            else:
                os.environ["EDGEGUARD_ENV"] = saved

    def test_query_api_gate_uses_is_prod(self):
        """The API-key requirement gate in query_api.py must consult the
        canonical helper, not the old ``_ENV == 'prod'`` strict-equality check."""
        src = (SRC / "query_api.py").read_text()
        # Negative: the broken gate must NOT remain.
        assert '_ENV == "prod"' not in src, (
            "query_api.py must not retain the ``_ENV == 'prod'`` gate (fails-open on typos)"
        )
        # Positive: gate must reference _IS_PROD (or call is_production_env()).
        assert "_IS_PROD" in src, "query_api.py must store + use _IS_PROD for the API-key gate"


# ===========================================================================
# Fix H2 — baseline_postcheck trigger_rule allows partial-failure diagnostics
# ===========================================================================


class TestH2BaselinePostcheckTriggerRule:
    """``baseline_postcheck_task`` must use ``NONE_FAILED_MIN_ONE_SUCCESS``
    (not ``ALL_SUCCESS``) so the INV-2 / INV-3 invariant probes still
    run after partial enrichment failure — exactly when operators most
    need them to triage."""

    def test_postcheck_uses_none_failed_min_one_success(self):
        text = (DAGS / "edgeguard_pipeline.py").read_text()
        # Find the baseline_postcheck_task definition + check trigger_rule.
        idx = text.find("baseline_postcheck_task")
        assert idx != -1, "baseline_postcheck_task not found in edgeguard_pipeline.py"
        # Scan forward ~3000 chars to find its trigger_rule kwarg.
        block = text[idx : idx + 3000]
        assert "NONE_FAILED_MIN_ONE_SUCCESS" in block, (
            "baseline_postcheck_task must use trigger_rule=NONE_FAILED_MIN_ONE_SUCCESS "
            "(post-N24 H2). Pre-N24 ALL_SUCCESS skipped the diagnostics on partial failure."
        )

    def test_postcheck_no_longer_uses_all_success(self):
        text = (DAGS / "edgeguard_pipeline.py").read_text()
        idx = text.find("baseline_postcheck_task")
        block = text[idx : idx + 3000]
        # The pre-N24 shape must NOT remain on the postcheck task.
        # (ALL_SUCCESS may still be the default for OTHER tasks — only
        # check inside the baseline_postcheck_task definition window.)
        assert "trigger_rule=TriggerRule.ALL_SUCCESS" not in block, (
            "baseline_postcheck_task must not use ALL_SUCCESS trigger_rule"
        )


# ===========================================================================
# Fix H3 — EdgeGuardMispEventAttributesTruncated alert wired in alerts.yml
# ===========================================================================


class TestH3MispEventAttributesTruncatedAlert:
    """The PR-N23 ``edgeguard_misp_event_attributes_truncated_total`` counter
    must have a paired alert that fires on non-zero rate."""

    def test_alert_present_in_alerts_yml(self):
        text = (PROMETHEUS / "alerts.yml").read_text()
        assert "EdgeGuardMispEventAttributesTruncated" in text, (
            "prometheus/alerts.yml must define the EdgeGuardMispEventAttributesTruncated "
            "alert that wires the PR-N23 counter to actionable observability"
        )

    def test_alert_uses_increase_not_rate(self):
        """Same lesson as PR-N12: ``rate(...) > 0`` is per-second; use
        ``increase()`` for absolute count over window."""
        text = (PROMETHEUS / "alerts.yml").read_text()
        idx = text.find("EdgeGuardMispEventAttributesTruncated")
        block = text[idx : idx + 1500]
        assert "increase(edgeguard_misp_event_attributes_truncated_total" in block, (
            "alert expr must use ``increase(edgeguard_misp_event_attributes_truncated_total[...])`` "
            "(absolute count) — NOT ``rate(...)`` which is per-second"
        )

    def test_alert_labelled_by_source(self):
        text = (PROMETHEUS / "alerts.yml").read_text()
        idx = text.find("EdgeGuardMispEventAttributesTruncated")
        block = text[idx : idx + 1500]
        assert "by (source)" in block, "alert must aggregate ``by (source)`` so operators see which feed is over-sized"

    def test_alert_severity_warning(self):
        text = (PROMETHEUS / "alerts.yml").read_text()
        idx = text.find("EdgeGuardMispEventAttributesTruncated")
        block = text[idx : idx + 1500]
        assert "severity: warning" in block, (
            "truncation is data-loss but recoverable (raise the cap or fix the source) — "
            "severity should be ``warning``, not ``critical`` (consistent with similar"
            " observability alerts)"
        )
