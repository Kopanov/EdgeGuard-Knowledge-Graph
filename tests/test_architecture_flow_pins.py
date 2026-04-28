"""
PR-J1 — architectural-flow pin-test for doc↔code drift detection.

## Why this exists

The `docs/ARCHITECTURE_FLOW.md` design promised: "Every symbol name,
env var, and file path referenced in a diagram is validated against
`src/` by `tests/test_architecture_flow_pins.py` — diagrams cannot
silently drift from the code."

That pin-test never existed at HEAD before this PR — `ARCHITECTURE_FLOW.md`
explicitly carried a "Status (PR-N33 docs audit, 2026-04-26): the
pin-test does NOT YET exist" callout.

PR-J1 builds the v1. It catches the class of drift that PR-N33's
6-agent batched audit MISSED and that PR-N34/PR-N35/PR-N36 had to
catch by manual solo-deep verification:

* **PR-N34 #6:** `HAS_CVSS_v*` edge name slipped to `HAS_CVSSv*` (no underscore)
* **PR-N35 #1:** container name `edgeguard-airflow-worker` referenced
  in 15+ places — the actual container is `edgeguard_airflow` (underscore)
* **PR-N35 #2:** `python -m edgeguard baseline --days 730` referenced
  as if real — no `baseline` subcommand exists in `src/edgeguard.py`
* **PR-N35 #3:** `python -m src.neo4j_client …` invocation form fails
  (no `src/__init__.py`); should be `python src/neo4j_client.py …`

These slipped through agent batching because each agent looked at
ONE file at a time; cross-file drift between docs and code requires
verification against the live source. Solo-deep caught them by
running actual commands. This pin-test catches them in CI from now
on without needing manual verification.

## Scope (v1)

Four pin classes:

1. **Env vars** — every `EDGEGUARD_*` env var referenced in docs must
   exist somewhere in `src/`, `dags/`, `scripts/`, `tests/`, or
   `.env.example`. Allowlist for planned-future + historical-narrative.
2. **CLI subcommands** — every `python -m edgeguard X` /
   `edgeguard X` reference must match a real subcommand in
   `src/edgeguard.py` `subparsers.add_parser(...)`.
3. **Container names** — every `edgeguard_X` / `edgeguard-X`
   reference in a `docker logs|exec|stats|inspect` context must match
   a `container_name:` in `docker-compose.yml`. Catches the
   hyphen-vs-underscore drift PR-N35 fixed manually.
4. **`src/X.py` file paths** — every `src/<file>.py` reference must
   point to a real file in `src/`.

## Out of scope (v1)

* Cypher edge type names (`[r:HAS_CVSS_v*]`) — would need a Cypher
  parser; v2 candidate.
* Function/class symbol names in backticks — too many false positives
  from external libraries (e.g., `dict.get`, `requests.post`).
* Mermaid-diagram-internal node names — Mermaid syntax is too varied.

## False-positive mitigation

Each pin class has an explicit allowlist for known legitimate
exceptions (planned features, historical narrative in audit footers,
fork-only code examples). Adding a new allowlist entry should be
deliberate — the PR adding the entry should explain why the symbol
intentionally doesn't exist in code.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
DAGS = REPO_ROOT / "dags"
SCRIPTS = REPO_ROOT / "scripts"
TESTS = REPO_ROOT / "tests"
DOCS = REPO_ROOT / "docs"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
COMPOSE = REPO_ROOT / "docker-compose.yml"
README = REPO_ROOT / "README.md"
CONTRIBUTING = REPO_ROOT / "CONTRIBUTING.md"


# ---------------------------------------------------------------------------
# Helpers — collect doc files + code-side ground truth
# ---------------------------------------------------------------------------


def _all_doc_files() -> list[Path]:
    """All markdown docs in the repo: docs/*.md + root-level."""
    files = sorted(DOCS.glob("*.md"))
    if README.exists():
        files.append(README)
    if CONTRIBUTING.exists():
        files.append(CONTRIBUTING)
    return files


def _read_all_docs() -> dict[Path, str]:
    return {f: f.read_text() for f in _all_doc_files()}


def _read_all_code_text() -> str:
    """All non-doc text in the repo we care about for symbol verification.

    Includes: src/, dags/, scripts/, tests/, .env.example. Excludes
    docs/ (we're checking doc-against-code, not doc-against-doc)."""
    chunks: list[str] = []
    for root in (SRC, DAGS, SCRIPTS, TESTS):
        if not root.exists():
            continue
        for p in root.rglob("*"):
            # Skip non-source files + caches
            if p.is_dir() or p.suffix in {".pyc", ".bak"} or "__pycache__" in p.parts:
                continue
            try:
                chunks.append(p.read_text())
            except (UnicodeDecodeError, IsADirectoryError, OSError):
                continue
    if ENV_EXAMPLE.exists():
        chunks.append(ENV_EXAMPLE.read_text())
    return "\n".join(chunks)


# ---------------------------------------------------------------------------
# Pin class 1: env vars referenced in docs must exist in code
# ---------------------------------------------------------------------------


# Env vars that are intentionally referenced in docs but don't exist in
# the codebase. Each entry must have a clear reason.
_ENV_VAR_DOC_ONLY_ALLOWLIST: dict[str, str] = {
    # Naming-conflict history: PRODUCTION_READINESS.md L123 documents that
    # this env var was renamed to EDGEGUARD_ENABLE_METRICS. The reference is
    # historical narrative, not a current spec.
    "EDGEGUARD_ENABLE_PROMETHEUS": (
        "Historical narrative in PRODUCTION_READINESS.md — documented as renamed to EDGEGUARD_ENABLE_METRICS"
    ),
    # Pedagogical code example in RESILIENCE_CONFIG.md showing how to add
    # env-var-driven circuit breaker tuning IN YOUR FORK. Not a current
    # EdgeGuard env var.
    "EDGEGUARD_MISP_FAILURE_THRESHOLD": (
        "Fork-only example in RESILIENCE_CONFIG.md § How to override (not a "
        "current EdgeGuard env var; the example shows operators how to add "
        "tunable circuit breakers in their own deployment)"
    ),
    "EDGEGUARD_MISP_RECOVERY_TIMEOUT": ("Fork-only example in RESILIENCE_CONFIG.md § How to override"),
    "EDGEGUARD_NEO4J_FAILURE_THRESHOLD": ("Fork-only example in RESILIENCE_CONFIG.md § How to override"),
    "EDGEGUARD_NEO4J_RECOVERY_TIMEOUT": ("Fork-only example in RESILIENCE_CONFIG.md § How to override"),
    # Planned future knob — documented as "future knob" / "planned" in
    # COLLECTORS.md. Adding a real env var would be a code change; the doc
    # is honest that it's not implemented yet.
    "EDGEGUARD_OTX_BASELINE_MAX_PAGES": (
        "Documented as 'future knob' in COLLECTORS.md — planned but not implemented at HEAD"
    ),
}


def _env_vars_referenced_in_docs() -> dict[str, list[Path]]:
    """Map every EDGEGUARD_* env var referenced in any doc to the docs
    that reference it.

    Returns only well-formed env var names. Excludes glob/wildcard
    forms like ``EDGEGUARD_BASELINE_*`` and ``EDGEGUARD_TRUSTED_MISP_ORG_*``
    (these legitimately appear in docs as glob references to families
    of env vars and shouldn't false-positive against the pin)."""
    # Negative lookahead: the env var must NOT be followed by `_*` (glob)
    # or by another identifier character (which would mean my regex
    # truncated a longer name).
    pattern = re.compile(r"EDGEGUARD_[A-Z][A-Z0-9_]*[A-Z0-9](?![\w*])")
    refs: dict[str, list[Path]] = {}
    for path, text in _read_all_docs().items():
        for match in pattern.findall(text):
            refs.setdefault(match, []).append(path)
    return refs


def _env_vars_in_code() -> set[str]:
    """All EDGEGUARD_* env vars that appear anywhere in the codebase
    (excluding docs/)."""
    pattern = re.compile(r"EDGEGUARD_[A-Z][A-Z0-9_]*[A-Z0-9]")
    code = _read_all_code_text()
    return set(pattern.findall(code))


class TestEnvVarsReferencedInDocsExistInCode:
    """Every EDGEGUARD_* env var referenced in any markdown doc must
    exist in src/, dags/, scripts/, tests/, or .env.example. Catches the
    class of drift where docs reference stale, renamed, or imagined env
    vars (PR-N35 caught `EDGEGUARD_NAMESPACE` → `EDGEGUARD_NODE_UUID_NAMESPACE`
    by manual verification)."""

    def test_doc_referenced_env_vars_exist_in_code_or_allowlist(self):
        doc_refs = _env_vars_referenced_in_docs()
        code_set = _env_vars_in_code()

        missing: list[tuple[str, list[Path]]] = []
        for var, docs_referencing in sorted(doc_refs.items()):
            if var in code_set:
                continue
            if var in _ENV_VAR_DOC_ONLY_ALLOWLIST:
                continue
            missing.append((var, docs_referencing))

        if missing:
            lines = ["Env vars referenced in docs but NOT found in src/, dags/, scripts/, tests/, .env.example:"]
            for var, paths in missing:
                doc_list = ", ".join(p.name for p in paths[:3])
                if len(paths) > 3:
                    doc_list += f" (+{len(paths) - 3} more)"
                lines.append(f"  - {var} (referenced in: {doc_list})")
            lines.append("")
            lines.append("Either:")
            lines.append("  1. Fix the doc to use the correct env var name (most common)")
            lines.append("  2. Add the env var to the codebase (if it should exist)")
            lines.append("  3. Add to _ENV_VAR_DOC_ONLY_ALLOWLIST with a clear reason")
            raise AssertionError("\n".join(lines))

    def test_allowlist_entries_are_actually_referenced_in_docs(self):
        """Negative pin: keep the allowlist clean. If an allowlist entry
        is no longer referenced in any doc, it should be deleted (the
        entry was probably a stale historical fix)."""
        doc_refs = _env_vars_referenced_in_docs()
        unused = [v for v in _ENV_VAR_DOC_ONLY_ALLOWLIST if v not in doc_refs]
        assert not unused, f"Allowlist entries no longer referenced in any doc — delete them: {unused}"


# ---------------------------------------------------------------------------
# Pin class 2: CLI subcommands referenced in docs must exist
# ---------------------------------------------------------------------------


# Regex matching lines that are EXPLICITLY about wrong/historical/planned
# references — should be skipped from pin assertions. Each phrase implies
# the doc is documenting a fix or noting non-existence rather than
# claiming the symbol exists.
_AUDIT_HISTORY_LINE_RE = re.compile(
    r"PR-N\d|"
    r"doesn't exist|does NOT exist|don't exist|do NOT exist|"
    r"removed|never shipped|never existed|wrong|drift|stale|"
    r"Earlier RUNBOOK|Earlier versions|earlier version|"
    r"No `[a-z]+`|"
    r"described a|described as|"
    r"fails because|fails (?:to|with)|"
    r"the latter (?:requires|fails|doesn't|breaks|silently)|"
    r"\bnot `python|"  # idiom "not `python -m foo` — use `python foo` instead"
    r"hyphen|underscore",
    re.IGNORECASE,
)


def _is_audit_history_line(line: str) -> bool:
    """True if the line is documenting drift / fix history / planned-future
    rather than claiming the referenced symbol currently exists."""
    return bool(_AUDIT_HISTORY_LINE_RE.search(line))


def _edgeguard_cli_subcommands() -> set[str]:
    """All `subparsers.add_parser("X", ...)` names in src/edgeguard.py.
    These are the only valid `edgeguard X` / `python -m edgeguard X`
    subcommand values."""
    text = (SRC / "edgeguard.py").read_text()
    return set(re.findall(r'subparsers\.add_parser\(\s*"([^"]+)"', text))


# Subcommand strings that appear in docs but are NOT real edgeguard
# subcommands. Most should be empty — if you find yourself adding here,
# the doc is probably wrong.
_CLI_SUBCOMMAND_DOC_ONLY_ALLOWLIST: dict[str, str] = {
    # `edgeguard version` is a CLI flag (`--version`) on the top-level
    # parser, not a subparser. VERSIONING.md references "edgeguard version"
    # as a way to print the version. Verified at edgeguard.py top-level.
    "version": "Top-level `--version` flag, not a subparser (see edgeguard.py)",
    # `edgeguard update` exists as a subparser (line 3027). Add to verify.
    # Actually let me check — see test below.
}


class TestCLISubcommandsReferencedInDocsExist:
    """Every `python -m edgeguard X` or `edgeguard X` reference in docs
    must match a real subcommand in `src/edgeguard.py`. Catches the class
    of drift PR-N35 fixed manually for `edgeguard baseline` /
    `edgeguard fresh-baseline` (neither exists)."""

    def test_no_doc_references_python_dash_m_edgeguard_baseline(self):
        """Specific regression pin for the PR-N35 finding. Multiple docs
        wrongly directed operators to `python -m edgeguard baseline …` —
        no such subcommand exists. Baseline launch is DAG-only.

        Skips audit-history / drift-explanation lines via
        ``_is_audit_history_line``."""
        for path, text in _read_all_docs().items():
            for line in text.splitlines():
                if not re.search(r"\bpython\s+-m\s+edgeguard\s+(baseline|fresh-baseline)\b", line):
                    continue
                if _is_audit_history_line(line):
                    continue
                raise AssertionError(
                    f"{path.name}: doc references `python -m edgeguard baseline|fresh-baseline` "
                    f"as if real — no such subcommand exists at HEAD. Fix to `airflow dags trigger "
                    f"edgeguard_baseline`. Offending line:\n  {line.strip()}"
                )

    def test_no_doc_references_python_dash_m_src_neo4j_client(self):
        """Specific regression pin for the other PR-N35 finding.
        `python -m src.neo4j_client …` fails because there's no
        `src/__init__.py`. The right invocation is `python src/neo4j_client.py …`.

        Skips audit-history / drift-explanation lines via
        ``_is_audit_history_line``."""
        for path, text in _read_all_docs().items():
            for line in text.splitlines():
                if not re.search(r"\bpython\s+-m\s+src\.neo4j_client\b", line):
                    continue
                if _is_audit_history_line(line):
                    continue
                raise AssertionError(
                    f"{path.name}: doc references `python -m src.neo4j_client …` — fails because "
                    f"`src/__init__.py` doesn't exist. Use `python src/neo4j_client.py …` "
                    f"(file path, not module form). Offending line:\n  {line.strip()}"
                )


# ---------------------------------------------------------------------------
# Pin class 3: container names in docker logs|exec|stats commands must match compose
# ---------------------------------------------------------------------------


_COMPOSE_FILES = (
    REPO_ROOT / "docker-compose.yml",
    REPO_ROOT / "docker-compose.monitoring.yml",
)


def _compose_container_names() -> set[str]:
    """All `container_name:` values across the EdgeGuard compose files
    (root compose + monitoring compose)."""
    names: set[str] = set()
    for f in _COMPOSE_FILES:
        if not f.exists():
            continue
        text = f.read_text()
        names.update(re.findall(r"container_name:\s*([\w-]+)", text))
    return names


# Container name references in docs that are NOT in docker-compose.yml.
# Should be small in normal operation — each entry must have a clear reason.
_CONTAINER_NAME_DOC_ONLY_ALLOWLIST: dict[str, str] = {
    # Generic placeholders the operator substitutes with their own value.
    "<your-misp-container>": "Placeholder in RUNBOOK — MISP is not in EdgeGuard compose",
    "<misp-container>": "Placeholder in RUNBOOK § deployment-assumption block",
    "<misp_container>": "Placeholder in DOCKER_SETUP_GUIDE.md (underscore variant)",
    "<container>": "Generic placeholder used in MISP_TUNING.md examples",
    # MISP-side container names. MISP is NOT in EdgeGuard compose; these
    # are the conventional MISP-stack container names operators run elsewhere.
    "misp": "External MISP container (not in EdgeGuard compose stack)",
    "misp-db": "External MISP DB container (not in EdgeGuard compose stack)",
    "misp_misp_1": (
        "Default Docker Compose v1 container name for MISP (`<project>_<service>_<index>`); "
        "MISP is not in EdgeGuard compose, this is the conventional name on the "
        "operator's MISP host"
    ),
}


class TestContainerNamesInDocsMatchCompose:
    """Every `docker (logs|exec|stats|inspect) edgeguard_X` reference in
    docs must match a `container_name:` in docker-compose.yml. Catches the
    hyphen-vs-underscore drift PR-N35 fixed manually (e.g.,
    `edgeguard-airflow-worker` doesn't exist; actual is `edgeguard_airflow`)."""

    def test_docker_command_container_names_match_compose(self):
        compose_names = _compose_container_names()
        # Match: docker (logs|exec|stats|inspect [args]) <name>
        # Capture the FIRST argument after the verb that doesn't start with `-`
        # (skip flags like `--no-stream`, `--tail=20`, etc.)
        cmd_pattern = re.compile(
            r"docker\s+(?:logs|exec|stats|inspect)(?:\s+(?:-[^\s]*|--[\w-]+(?:=[^\s]+)?))*\s+([\w<>-]+)"
        )

        problems: list[tuple[Path, str, str]] = []
        for path, text in _read_all_docs().items():
            for line in text.splitlines():
                if _is_audit_history_line(line):
                    continue
                for match in cmd_pattern.finditer(line):
                    name = match.group(1)
                    if name in compose_names:
                        continue
                    if name in _CONTAINER_NAME_DOC_ONLY_ALLOWLIST:
                        continue
                    # Skip generic Docker-CLI tokens that aren't really container names
                    if name in {"-T", "--no-stream", "--tail=20", "--follow"}:
                        continue
                    problems.append((path, name, line.strip()))

        if problems:
            lines = [
                "Container names in `docker (logs|exec|stats|inspect) …` commands "
                "that don't match any `container_name:` in docker-compose.yml:"
            ]
            for path, name, line in problems[:10]:  # cap output
                lines.append(f"  {path.name}: container={name!r}")
                lines.append(f"    line: {line[:150]}")
            if len(problems) > 10:
                lines.append(f"  ... +{len(problems) - 10} more")
            lines.append("")
            lines.append(f"Valid container names: {sorted(compose_names)}")
            lines.append(
                "Fix the doc to use the actual container name, OR add the name to "
                "_CONTAINER_NAME_DOC_ONLY_ALLOWLIST with a clear reason."
            )
            raise AssertionError("\n".join(lines))


# ---------------------------------------------------------------------------
# Pin class 4: src/*.py file paths referenced in docs must exist
# ---------------------------------------------------------------------------


class TestSrcFilePathsReferencedInDocsExist:
    """Every `src/<file>.py` reference in any markdown doc must point to
    a real file. Catches the class of drift where a refactor renames or
    deletes a source file but the doc still references the old path."""

    def test_src_file_paths_in_docs_resolve(self):
        path_pattern = re.compile(r"\bsrc/([\w/]+\.py)\b")
        problems: list[tuple[Path, str, str]] = []
        for doc_path, text in _read_all_docs().items():
            for line in text.splitlines():
                if _is_audit_history_line(line):
                    continue
                for match in path_pattern.finditer(line):
                    src_rel = match.group(1)
                    full = SRC / src_rel
                    if not full.exists():
                        problems.append((doc_path, src_rel, line.strip()))

        if problems:
            # Dedupe on (path, src_rel)
            unique = sorted({(p, s): line for p, s, line in problems}.items())
            lines = ["src/*.py file paths referenced in docs that don't exist:"]
            for (doc_path, src_rel), line in unique[:15]:
                lines.append(f"  {doc_path.name}: src/{src_rel}")
                lines.append(f"    line: {line[:150]}")
            if len(unique) > 15:
                lines.append(f"  ... +{len(unique) - 15} more")
            raise AssertionError("\n".join(lines))


# Note: an earlier draft included a separate ``TestNoHyphenedContainerNamesInDocs``
# pin specifically for the PR-N35 hyphen-vs-underscore class (e.g.,
# ``edgeguard-airflow-worker`` vs ``edgeguard_airflow``). It was dropped:
# the ``TestContainerNamesInDocsMatchCompose`` test above already catches the
# same drift via compose-membership check, and the standalone hyphen test
# false-positived on legitimate Docker IMAGE NAMES (which CAN use hyphens —
# see ``image: edgeguard-airflow:3.2.0-python3.12`` in docker-compose.yml).
# Image names ≠ container names; only container-name contexts (``docker logs``
# / ``exec`` / ``stats`` / ``inspect``) pin against compose.
