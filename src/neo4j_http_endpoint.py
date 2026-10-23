"""The Neo4j HTTP Query API address and requests of the host-side scripts.

``scripts/verify_fresh_baseline.py``, ``scripts/run_cypher_catalog_http.py`` and
``scripts/build_canonical_threat_actors.py`` read Neo4j over the HTTP Query API v2 and send
``NEO4J_USER`` / ``NEO4J_PASSWORD`` as basic auth. They build every request here, so they read the
same settings and send the credentials only to the configured address or to the local Compose
Neo4j:

- the address is ``NEO4J_HTTP_URL``, then ``NEO4J_HTTP`` (the name ``docker-compose.yml`` and
  ``.env.example`` use for the same endpoint); a set value must be an ``http://`` or ``https://``
  URL with a host, a numeric port from 0 to 65535 when it names one, and no space or control
  character. Any other is refused (:class:`Neo4jHttpEndpointError`) before a request is built,
  so the scripts exit 2 instead of failing in ``urllib`` with ``http.client.InvalidURL``;
- with neither set (or both empty) it is :data:`LOCAL_COMPOSE_HTTP_URL`, the HTTP port the
  ``neo4j`` service of ``docker-compose.yml`` publishes on host loopback. There is no remote
  default;
- ``NEO4J_DATABASE`` names the database of the path (unset or empty: ``neo4j``), ``NEO4J_USER``
  (default ``neo4j``) and ``NEO4J_PASSWORD`` the credentials;
- ``NEO4J_HTTP_USER_AGENT`` sets the User-Agent; unset or empty it is a browser's, because a
  Cloudflare proxy in front of a hosted instance rejects urllib's default agent (HTTP 403,
  error 1010).

Settings are read when a function is called, not at import. Standard library only, like the other
modules the scripts import from ``src/``.
"""

from __future__ import annotations

import base64
import os
import re
import urllib.parse
import urllib.request
from typing import Mapping, Optional

# docker-compose.yml, service neo4j: ``ports: - "127.0.0.1:7474:7474"`` (pinned by a test).
LOCAL_COMPOSE_HTTP_URL = "http://127.0.0.1:7474"
# Read in this order; the first set value wins.
URL_VARIABLES = ("NEO4J_HTTP_URL", "NEO4J_HTTP")
# Characters http.client refuses in a request URL (``_contains_disallowed_url_pchar_re``).
_DISALLOWED_URL_CHAR = re.compile(r"[\x00-\x20\x7f]")
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


class Neo4jHttpEndpointError(ValueError):
    """``NEO4J_HTTP_URL`` or ``NEO4J_HTTP`` is set to something other than an http(s) URL with a host,
    a valid port (when it names one) and no space or control character."""


def _env(environ: Optional[Mapping[str, str]]) -> Mapping[str, str]:
    return os.environ if environ is None else environ


def base_url(environ: Optional[Mapping[str, str]] = None) -> str:
    """The Neo4j HTTP base URL, without a trailing slash."""
    env = _env(environ)
    for name in URL_VARIABLES:
        value = (env.get(name) or "").strip()
        if not value:
            continue
        unset_note = f"(unset, the scripts use the local Compose Neo4j {LOCAL_COMPOSE_HTTP_URL})"
        parts = urllib.parse.urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname or _DISALLOWED_URL_CHAR.search(value):
            raise Neo4jHttpEndpointError(
                f"{name}={value!r} is not an http:// or https:// URL with a host and no space {unset_note}"
            )
        try:
            _ = parts.port  # a non-numeric or out-of-range port raises ValueError
        except ValueError as exc:
            raise Neo4jHttpEndpointError(f"{name}={value!r} has an invalid port: {exc} {unset_note}") from None
        return value.rstrip("/")
    return LOCAL_COMPOSE_HTTP_URL


def database(environ: Optional[Mapping[str, str]] = None) -> str:
    return _env(environ).get("NEO4J_DATABASE") or "neo4j"


def user(environ: Optional[Mapping[str, str]] = None) -> str:
    return _env(environ).get("NEO4J_USER", "neo4j")


def user_agent(environ: Optional[Mapping[str, str]] = None) -> str:
    return _env(environ).get("NEO4J_HTTP_USER_AGENT") or BROWSER_USER_AGENT


def query_api_url(environ: Optional[Mapping[str, str]] = None) -> str:
    """The Query API v2 endpoint of the database: ``<base>/db/<database>/query/v2``."""
    return f"{base_url(environ)}/db/{database(environ)}/query/v2"


def query_request(body: bytes, environ: Optional[Mapping[str, str]] = None) -> urllib.request.Request:
    """A POST of ``body`` (the JSON request) to :func:`query_api_url`, with basic auth, JSON headers
    and :func:`user_agent`. Raises :class:`Neo4jHttpEndpointError` before building it when the
    configured address is not a valid http(s) URL (:func:`base_url`)."""
    env = _env(environ)
    req = urllib.request.Request(query_api_url(env), data=body, method="POST")
    token = base64.b64encode(f"{user(env)}:{env.get('NEO4J_PASSWORD', '')}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", user_agent(env))
    return req
