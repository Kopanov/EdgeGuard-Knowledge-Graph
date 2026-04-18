"""Security PR regression pins for the auth + API hardening fixes batch.

Closes Tier S/A items from the proactive Red Team audit:

* **S6** AIRFLOW_API_PASSWORD default ``"airflow"`` — now SKIPS DAG check
  when unset instead of using the default credential
* **S7** ``verify=False`` hardcoded in cmd_doctor MISP probe — now uses
  ``SSL_VERIFY``
* **S8** GraphQL no query depth/complexity limits — now caps depth at 8
  via ``QueryDepthLimiter`` extension
* **A6** ``EDGEGUARD_API_KEY`` only enforced in prod — now refuses to
  start unauthenticated on a non-loopback bind in any env
* **A7** GraphQL introspection on by default — now disabled in prod
  via ``NoSchemaIntrospectionCustomRule``
* **A8** No SSRF guards on collectors — now ``allow_redirects=False``
  default in the shared ``request_with_rate_limit_retries`` helper
* **A9** No bound on inbound MISP attribute size — now 4 KB cap
  (configurable via ``EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES``)
"""

from __future__ import annotations

import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# S7 — cmd_doctor MISP probe must use SSL_VERIFY, not hardcoded False
# ---------------------------------------------------------------------------


def _code_only(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_cmd_doctor_misp_probe_does_not_use_verify_false():
    """Source-grep pin: the cmd_doctor MISP /events/index probe must NOT
    use ``verify=False`` (would send the API key over MITM-able TLS)."""
    path = os.path.join(_SRC, "edgeguard.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    # Locate the MISP probe block
    probe_start = src.find("/events/index")
    assert probe_start > 0, "could not locate MISP /events/index probe in edgeguard.py"
    # Walk ~30 lines forward
    window = src[probe_start : probe_start + 1500]
    assert "verify=False" not in window, (
        "cmd_doctor MISP probe MUST NOT use verify=False — sends API key over MITM-able TLS. "
        "Use SSL_VERIFY (the configured default) instead."
    )
    assert "verify=SSL_VERIFY" in window, "MISP probe must explicitly pass verify=SSL_VERIFY"


# ---------------------------------------------------------------------------
# S6 — AIRFLOW_API_PASSWORD must NOT default to "airflow"
# ---------------------------------------------------------------------------


def test_cmd_doctor_does_not_default_airflow_password_to_airflow():
    """Source-grep pin: the previous
    ``os.getenv("AIRFLOW_API_PASSWORD", "airflow")`` is the smoking gun.
    Default credentials must NOT be silently used."""
    path = os.path.join(_SRC, "edgeguard.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    assert 'os.getenv("AIRFLOW_API_PASSWORD", "airflow")' not in src, (
        "AIRFLOW_API_PASSWORD must NOT default to the literal 'airflow' — "
        "operators who skip setting it would expose the Airflow REST API "
        "(DAG triggering, task-instance reset) to anyone reaching port 8082"
    )
    # Positive pin: must use the empty-string default + skip-if-empty pattern
    assert 'os.getenv("AIRFLOW_API_PASSWORD", "")' in src, (
        "use the empty-default + skip pattern so unset env → skip API check, not weak auth"
    )


# ---------------------------------------------------------------------------
# S8 — GraphQL must enforce a query depth cap
# ---------------------------------------------------------------------------


def test_graphql_schema_includes_query_depth_limiter():
    """Pin the QueryDepthLimiter extension. Without it, an attacker can
    issue deeply-nested queries that fan out into dozens of OPTIONAL MATCH
    joins per resolver and exhaust the Neo4j bolt pool."""
    import graphql_api

    schema_extensions = getattr(graphql_api.schema, "extensions", []) or []
    extension_class_names = [type(e).__name__ for e in schema_extensions]
    assert "QueryDepthLimiter" in extension_class_names, (
        f"GraphQL schema must include QueryDepthLimiter extension; got extensions: {extension_class_names}"
    )


def test_graphql_max_depth_default_is_reasonable():
    """The default max depth (8) must be > 0 and < some absurd value.
    8 is well above the deepest legitimate query (CVE → vuln → indicator
    → malware → technique → tactic = 6) and well below an unbounded
    DoS surface."""
    import graphql_api

    assert 4 <= graphql_api._GRAPHQL_MAX_DEPTH <= 16, (
        f"GraphQL max depth must be a sane positive bounded value; got {graphql_api._GRAPHQL_MAX_DEPTH}"
    )


# ---------------------------------------------------------------------------
# A7 — GraphQL introspection must be disabled in prod
# ---------------------------------------------------------------------------


def test_graphql_introspection_disabled_in_prod(monkeypatch):
    """When EDGEGUARD_ENV=prod, the schema must include the
    NoSchemaIntrospectionCustomRule validation. Without it,
    reconnaissance probes can pull the entire schema even when the
    GraphiQL playground is disabled."""
    # Reload graphql_api with the prod env var set so the module re-evaluates
    # _IS_PROD and re-builds _extensions accordingly.
    monkeypatch.setenv("EDGEGUARD_ENV", "prod")
    monkeypatch.setenv("EDGEGUARD_API_KEY", "test-key-must-be-set-in-prod")
    monkeypatch.setenv("EDGEGUARD_API_HOST", "127.0.0.1")  # loopback so A6 doesn't refuse

    import importlib

    if "graphql_api" in sys.modules:
        del sys.modules["graphql_api"]
    import graphql_api

    importlib.reload(graphql_api)

    schema_extensions = getattr(graphql_api.schema, "extensions", []) or []
    extension_class_names = [type(e).__name__ for e in schema_extensions]
    assert "AddValidationRules" in extension_class_names, (
        f"In prod, schema must include AddValidationRules (carrying NoSchemaIntrospectionCustomRule); "
        f"got: {extension_class_names}"
    )

    # Cleanup: reload once more without prod so other tests get back to baseline
    monkeypatch.delenv("EDGEGUARD_ENV", raising=False)
    monkeypatch.delenv("EDGEGUARD_API_KEY", raising=False)
    monkeypatch.delenv("EDGEGUARD_API_HOST", raising=False)
    if "graphql_api" in sys.modules:
        del sys.modules["graphql_api"]


def test_graphql_introspection_left_on_in_dev(monkeypatch):
    """Negative pin: in dev/staging, introspection MUST stay on so
    developers can use GraphiQL / Apollo Studio / schema autocomplete."""
    monkeypatch.delenv("EDGEGUARD_ENV", raising=False)  # default: dev
    monkeypatch.delenv("EDGEGUARD_API_KEY", raising=False)
    monkeypatch.setenv("EDGEGUARD_API_HOST", "127.0.0.1")

    import importlib

    if "graphql_api" in sys.modules:
        del sys.modules["graphql_api"]
    import graphql_api

    importlib.reload(graphql_api)

    schema_extensions = getattr(graphql_api.schema, "extensions", []) or []
    extension_class_names = [type(e).__name__ for e in schema_extensions]
    # AddValidationRules is the carrier for the introspection-disable rule;
    # in dev it must NOT be present (or if present, must not carry the rule).
    # Cheapest pin: assert it's absent in dev.
    assert "AddValidationRules" not in extension_class_names, (
        "Dev mode must NOT add the introspection-disable rule (developers need GraphiQL)"
    )


# ---------------------------------------------------------------------------
# A6 — Refuse to start unauthenticated on non-loopback bind
# ---------------------------------------------------------------------------


def test_query_api_refuses_to_start_unauthenticated_on_external_bind(monkeypatch):
    """Source-grep pin: query_api.py must refuse to start (raise
    RuntimeError) when EDGEGUARD_API_KEY is unset AND the bind host
    is not loopback AND EDGEGUARD_ALLOW_UNAUTH is not set.

    Direct import-time check would also work but is harder to test in
    isolation because importing query_api boots the full Neo4j driver
    and FastAPI app. Source-grep is the practical pin."""
    path = os.path.join(_SRC, "query_api.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    assert "Refusing to start an unauthenticated REST API" in src, (
        "query_api.py must refuse to start when EDGEGUARD_API_KEY is unset "
        "AND bound to a non-loopback host (without explicit EDGEGUARD_ALLOW_UNAUTH=1)"
    )
    assert "EDGEGUARD_ALLOW_UNAUTH" in src, "must offer the explicit opt-in escape hatch"


def test_graphql_api_refuses_to_start_unauthenticated_on_external_bind():
    """Same contract for graphql_api.py."""
    path = os.path.join(_SRC, "graphql_api.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    assert "Refusing to start an unauthenticated GraphQL endpoint" in src, (
        "graphql_api.py must refuse to start when EDGEGUARD_API_KEY is unset AND bound to a non-loopback host"
    )
    assert "EDGEGUARD_ALLOW_UNAUTH" in src


def test_graphql_api_security_check_reads_same_env_as_actual_bind():
    """PR #40 commit X (bugbot HIGH) regression pin.

    The bind-host security check MUST read the same env var the server
    actually binds to. Previously the check read ``EDGEGUARD_API_HOST``
    first (a REST-API var; GraphQL server never honors it), then fell
    back to ``EDGEGUARD_GRAPHQL_HOST``. An operator setting
    ``EDGEGUARD_API_HOST=127.0.0.1`` + ``EDGEGUARD_GRAPHQL_HOST=0.0.0.0``
    would PASS the safety check (sees 127.0.0.1 from API_HOST) while
    the server actually bound to 0.0.0.0 unauthenticated.

    Pin: the security check env var === the actual-bind env var.
    """
    path = os.path.join(_SRC, "graphql_api.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    # The security check should NOT consult EDGEGUARD_API_HOST
    # (that's a REST-only var the GraphQL server doesn't honor)
    assert 'os.getenv("EDGEGUARD_API_HOST"' not in src, (
        "graphql_api.py security check must NOT read EDGEGUARD_API_HOST — "
        "that env var is for REST API only; GraphQL server reads "
        "EDGEGUARD_GRAPHQL_HOST. Mixed precedence creates a bypass."
    )
    # Both the security check and the server bind must read the same var
    assert src.count('os.getenv("EDGEGUARD_GRAPHQL_HOST"') >= 2, (
        "graphql_api.py must read EDGEGUARD_GRAPHQL_HOST in BOTH the security check AND the actual server bind"
    )


# ---------------------------------------------------------------------------
# A8 — Collectors must NOT follow redirects by default
# ---------------------------------------------------------------------------


def test_collector_helper_disables_redirects_by_default():
    """Source-grep pin on the shared helper: SSRF guard via
    ``allow_redirects=False`` default.

    If absent, a hijacked upstream feed could redirect to
    169.254.169.254 (cloud metadata) or 127.0.0.1:7474 (Neo4j Browser)
    and the response body would land in MISP + Neo4j."""
    path = os.path.join(_SRC, "collectors", "collector_utils.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    # The helper must explicitly setdefault allow_redirects to False
    assert 'kwargs.setdefault("allow_redirects", False)' in src, (
        "request_with_rate_limit_retries must set allow_redirects=False default"
    )


def test_collector_helper_allows_caller_override():
    """The default is False but caller can pass True explicitly when
    redirect-following is genuinely needed and the destination is trusted."""
    from unittest.mock import MagicMock, patch

    from collectors.collector_utils import request_with_rate_limit_retries

    fake_resp = MagicMock(status_code=200)
    with patch("collectors.collector_utils.requests.request", return_value=fake_resp) as mock_req:
        request_with_rate_limit_retries("GET", "https://example.com", allow_redirects=True)
    # The request was called with allow_redirects=True (caller override honored)
    assert mock_req.call_args.kwargs.get("allow_redirects") is True


def test_collector_helper_default_blocks_redirects():
    """Default path: caller doesn't pass allow_redirects → False enforced."""
    from unittest.mock import MagicMock, patch

    from collectors.collector_utils import request_with_rate_limit_retries

    fake_resp = MagicMock(status_code=200)
    with patch("collectors.collector_utils.requests.request", return_value=fake_resp) as mock_req:
        request_with_rate_limit_retries("GET", "https://example.com")
    assert mock_req.call_args.kwargs.get("allow_redirects") is False


# ---------------------------------------------------------------------------
# A9 — MISP attribute value size cap
# ---------------------------------------------------------------------------


def test_parse_attribute_rejects_oversized_value(monkeypatch):
    """A 100KB attribute value (> 4KB default cap) must be REFUSED
    rather than ingested into Neo4j. Without this, a poisoned upstream
    feed crashes the sync worker (OOM) and bloats Neo4j page cache."""
    # Force a small cap so the test doesn't allocate megabytes
    monkeypatch.setenv("EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES", "100")

    # Defer the heavy imports; bypass __init__ so we don't try to connect to MISP
    import sys as _sys

    # run_misp_to_neo4j requires several deps; if it fails to import in the
    # test env, skip rather than fail
    try:
        if "run_misp_to_neo4j" in _sys.modules:
            del _sys.modules["run_misp_to_neo4j"]
        import run_misp_to_neo4j
    except Exception:
        import pytest

        pytest.skip("run_misp_to_neo4j not importable in this env")

    sync = run_misp_to_neo4j.MISPToNeo4jSync.__new__(run_misp_to_neo4j.MISPToNeo4jSync)
    # Parse an attribute with a 200-byte value (exceeds the 100-byte test cap)
    oversized = "X" * 200
    item, rels = sync.parse_attribute(
        {"type": "ip-src", "value": oversized, "uuid": "test-uuid"},
        {"id": 42, "info": "test", "date": "2026-04-18", "Tag": []},
    )
    assert item is None, f"oversized attribute must be refused; got item={item}"
    assert rels == [], "oversized attribute must produce no relationships"


def test_parse_attribute_accepts_normal_value():
    """Negative pin: a normal-sized value (well under 4KB default) must
    parse normally — the cap must not break the happy path."""
    import sys as _sys

    try:
        if "run_misp_to_neo4j" in _sys.modules:
            del _sys.modules["run_misp_to_neo4j"]
        import run_misp_to_neo4j
    except Exception:
        import pytest

        pytest.skip("run_misp_to_neo4j not importable in this env")

    sync = run_misp_to_neo4j.MISPToNeo4jSync.__new__(run_misp_to_neo4j.MISPToNeo4jSync)
    # Normal IPv4 (15 chars) — well under any sane cap
    item, _ = sync.parse_attribute(
        {"type": "ip-src", "value": "203.0.113.5", "uuid": "test-uuid"},
        {"id": 42, "info": "test", "date": "2026-04-18", "Tag": []},
    )
    assert item is not None, "normal-sized attribute must parse — cap must not break happy path"
