"""Runtime version capture + recommended-version comparison for EdgeGuard.

Why this module exists
----------------------
Vanko's PR #36 audit (CyberCure follow-up) caught two adjacent gaps:

1. The pinned Neo4j docker image (``neo4j:5.26.23-community``) drifted from
   what was actually running locally (Neo4j 2026.03.x). When a server has
   moved to a new release line (5.x → 2026.x) but the docker-compose pin
   is stale, ``docker-compose up`` happily recreates the container at the
   pinned (older) version, silently rolling back the operator's data layer
   on the next ``down``/``up`` cycle. By the time someone notices, the
   APOC procedures and call signatures may have shifted under them.

2. Neither ``edgeguard doctor`` nor ``edgeguard validate`` reported the
   ACTUAL running version of any dependency. The operator had no
   visibility into "what version is actually on this host vs. what the
   project expects." A mismatch only surfaced via mysterious runtime
   errors (the Cypher query that failed because a syntax shifted; the
   PyMISP method that no longer existed; etc.).

This module closes both gaps with a single primitive: a small set of
``get_*_version()`` capture functions plus a ``RECOMMENDED_VERSIONS``
table sourced from ``requirements.txt`` / ``docker-compose.yml`` /
``Dockerfile.airflow``. ``compare_pinned_vs_running()`` produces a
structured report that ``cmd_doctor`` + ``cmd_validate`` render.

Design notes
------------
* All ``get_*_version()`` functions are best-effort and NEVER raise — they
  return ``None`` on any failure. Doctor/validate must never crash because
  the version capture failed; that defeats the user-visible benefit.
* Comparison is permissive on the patch component (``5.27.0`` matches
  ``~=5.27`` even though the running driver is ``5.27.1``). We only
  warn on minor/major drift because patch upgrades are by definition
  non-breaking under the project's ``~=`` SemVer policy (see the comment
  block in ``requirements.txt`` documenting why we use ``~=``).
* Server vs. driver are reported separately for Neo4j because they upgrade
  on independent cycles — the operator may pin the server line but allow
  driver patch-level upgrades.
* We deliberately do NOT block on version mismatches (no ``return 1``
  from doctor on a mismatch alone). The signal is informational; if the
  operator KNOWS they're on a newer line that's OK with our driver,
  forcing them to bump the pin would be friction without value.

Recommended versions are kept in this module rather than parsed from
``requirements.txt`` at runtime. Two reasons:
* The ``~=N.M`` form is hard to compare meaningfully without bringing
  in ``packaging.specifiers`` (extra dep just for a doctor check).
* Source-of-truth here is the bumped pin from PR #36 itself; if a
  future PR forgets to update both this table AND the pin file, the new
  ``test_recommended_versions_match_pin_files`` test catches it.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Recommended pins — source of truth for the version-compat report
# ---------------------------------------------------------------------------
#
# When you bump a pin in ``docker-compose.yml`` / ``requirements.txt`` /
# ``Dockerfile.airflow``, ALSO bump it here. The
# ``test_recommended_versions_match_pin_files`` regression test fails
# loudly if the two drift apart.
#
# Format: each value is the EXACT recommended major.minor. The compat
# check is "ok" only on an exact major.minor match (patch drift is
# silently fine — that's what the project's ``~=N.M`` SemVer policy
# in ``requirements.txt`` already documents as non-breaking). ANY
# minor drift in either direction is "warn":
#   * older running version → operator hasn't upgraded yet
#   * newer running minor   → someone bypassed the ``~=`` pin (manual
#     install, container override, custom build) and the documented
#     baseline no longer matches the deployed env
# Major drift additionally calls out likely breaking changes —
# operators should verify Cypher / API call sites before deploying.
# (PR #36 bugbot MED — was previously labeled "MINIMUM" which conflicted
# with the actual exact-match-on-major.minor behavior; the label
# created a trap for future developers reading the comment in
# isolation.)
RECOMMENDED_VERSIONS: Dict[str, str] = {
    # Neo4j server: we run the 2026.x community edition. Server release
    # line moved from 5.x → 2026.x in early 2026 (CalVer rebrand). The 5.x
    # Python driver is still wire-compat per Neo4j's official matrix —
    # see https://neo4j.com/developer/kb/neo4j-supported-versions/ — so
    # we don't force a driver bump in the same PR.
    "neo4j_server": "2026.03",
    # Neo4j Python driver: still on the 5.x line. Bumping to 6.x is a
    # major version change — separate PR with explicit testing.
    "neo4j_driver": "5.27",
    # Apache Airflow: 3.2.x baked into the custom image (Dockerfile.airflow
    # ``FROM apache/airflow:3.2.0-python3.12``).
    "airflow": "3.2",
    # PyMISP — talks to MISP 2.4.x.
    "pymisp": "2.4",
    # MISP server. We don't bump aggressively; 2.4.x is the long-running
    # line that's compatible with current PyMISP.
    "misp_server": "2.4",
}


# ---------------------------------------------------------------------------
# Version capture — every function MUST be best-effort + never raise
# ---------------------------------------------------------------------------


def get_neo4j_driver_version() -> Optional[str]:
    """Read ``neo4j.__version__`` if the package is importable.

    The driver always exposes this attribute on the top-level module
    (https://neo4j.com/docs/api/python-driver/). Returns ``None`` if the
    driver isn't installed (e.g. running ``edgeguard doctor`` from a slim
    container without Neo4j integration).
    """
    try:
        import neo4j  # noqa: WPS433 — runtime import is intentional

        v = getattr(neo4j, "__version__", None)
        return str(v) if v else None
    except Exception as e:  # noqa: BLE001 — best-effort; doctor must not crash
        logger.debug(f"neo4j driver version capture failed: {e}")
        return None


def get_neo4j_server_version(neo4j_client_factory=None) -> Optional[str]:
    """Query the running Neo4j server for its version string.

    Uses ``CALL dbms.components() YIELD versions`` which has been the
    canonical version-discovery procedure since 3.x. Result format:
    ``[{"versions": ["5.27.0"]}]`` (list-of-strings inside the row).

    ``neo4j_client_factory`` lets tests inject a mock client without
    needing a live Neo4j. In production it defaults to a FAST one-shot
    driver session (see below).

    Best-effort; returns ``None`` on any error including connection
    failure (we'd rather degrade silently in doctor than block on Neo4j
    being down — there are other doctor checks that already report that).

    PR #36 commit X (bugbot MED): when no factory is provided, this
    function used to instantiate ``Neo4jClient()`` and call ``connect()``,
    which is decorated with ``@retry_with_backoff(max_retries=5,
    base_delay=2)`` → up to ~62s of exponential backoff when Neo4j is
    unreachable. Both ``cmd_doctor`` and ``cmd_validate`` already run
    their own Neo4j connection check earlier in the flow with the same
    retry behavior, so version capture added a SECOND full retry cycle
    — wall-clock roughly doubled on a Neo4j outage for zero diagnostic
    value. The default-factory path now uses the Neo4j driver
    DIRECTLY with a tight ``connection_timeout`` so the version probe
    fails fast (a few seconds) instead of retrying. Test paths still go
    through the factory hook — the contract for ``test_get_neo4j_server_version_*``
    is unchanged.
    """
    if neo4j_client_factory is None:
        return _get_neo4j_server_version_fast()

    client = None
    try:
        client = neo4j_client_factory()
        # Some test factories return an instance directly without needing connect()
        if hasattr(client, "connect") and not client.connect():
            return None
        # PR #36 commit X (bugbot MED): Neo4j 2025.05+ added a "Cypher" row
        # to ``CALL dbms.components()`` output. Filter to ``Neo4j Kernel``
        # explicitly so we never pick the Cypher-language version row by
        # accident (would falsely report server as e.g. "5" instead of
        # "2026.03.1"). Same Cypher as in ``_get_neo4j_server_version_fast``
        # — keep them in lockstep.
        rows = client.run("CALL dbms.components() YIELD name, versions WHERE name = 'Neo4j Kernel' RETURN versions")
        if not rows:
            return None
        versions = rows[0].get("versions") if isinstance(rows[0], dict) else None
        if isinstance(versions, list) and versions:
            return str(versions[0])
        return None
    except Exception as e:  # noqa: BLE001
        logger.debug(f"neo4j server version capture failed: {e}")
        return None
    finally:
        if client is not None and hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass


def _get_neo4j_server_version_fast() -> Optional[str]:
    """Production path for ``get_neo4j_server_version``: bypass
    ``Neo4jClient.connect()``'s retry decorator.

    Uses the official Neo4j Python driver directly with a 2-second
    ``connection_timeout`` so a probe against a down Neo4j fails in
    seconds rather than the ~62 seconds that the retry-decorated
    ``Neo4jClient.connect()`` takes.

    Test paths must call ``get_neo4j_server_version(neo4j_client_factory=...)``
    instead — that branch keeps the existing test contract.
    """
    try:
        from config import NEO4J_PASSWORD, NEO4J_URI, NEO4J_USER  # noqa: WPS433
        from neo4j import GraphDatabase  # noqa: WPS433
    except Exception as e:  # noqa: BLE001
        logger.debug(f"neo4j driver / config import failed: {e}")
        return None

    driver = None
    try:
        # ``connection_timeout`` is the per-connection acquisition timeout;
        # ``max_connection_lifetime`` keeps the pooled connection short-lived
        # since this driver is single-shot. Both keep us from hanging on a
        # half-up Neo4j (TCP accept but no Bolt response).
        driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD),
            connection_timeout=2.0,
            max_connection_lifetime=10,
        )
        with driver.session(default_access_mode="READ") as session:
            # PR #36 commit X (bugbot MED): Neo4j 2025.05+ added a "Cypher"
            # row to ``CALL dbms.components()`` output (with ``versions:
            # ["5", "25"]`` — the Cypher language version). Without an
            # explicit ``WHERE name = 'Neo4j Kernel'`` filter, ``rows[0]``
            # may pick up the Cypher row instead of the kernel row →
            # we'd report the server version as ``"5"`` and the doctor
            # check would falsely scream MAJOR drift on the new
            # ``neo4j:2026.03.1-community`` image.
            #
            # Filter at the Cypher layer so we never have to guess from
            # row order. The query still returns ``[]`` on Neo4j forks
            # that don't expose the canonical "Neo4j Kernel" component
            # name; the caller already handles None gracefully.
            result = session.run(
                "CALL dbms.components() YIELD name, versions WHERE name = 'Neo4j Kernel' RETURN versions"
            )
            rows = list(result)
        if rows:
            row = rows[0]
            versions = row.get("versions") if hasattr(row, "get") else None
            if isinstance(versions, list) and versions:
                return str(versions[0])
        return None
    except Exception as e:  # noqa: BLE001
        # Includes ServiceUnavailable, AuthError, etc. — all best-effort failures.
        logger.debug(f"neo4j server version fast probe failed: {e}")
        return None
    finally:
        if driver is not None:
            try:
                driver.close()
            except Exception:
                pass


def get_airflow_version() -> Optional[str]:
    """Read Airflow's version.

    Two probes, in order of cost:
    1. ``import airflow; airflow.__version__`` — instant if installed in
       the same Python env (Airflow worker / scheduler containers).
    2. ``airflow version`` subprocess — fallback for when EdgeGuard CLI
       is invoked from a host shell that has the ``airflow`` binary on
       ``$PATH`` but the import would fail (different venv).

    Subprocess output format: a banner followed by the version on its
    own line (e.g. ``3.2.0``). We strip and grab the first line that
    matches ``^\\d+\\.\\d+(\\.\\d+)?$``.
    """
    # Probe 1: import path
    try:
        import airflow  # noqa: WPS433

        v = getattr(airflow, "__version__", None)
        if v:
            return str(v)
    except Exception:
        pass

    # Probe 2: subprocess fallback
    try:
        result = subprocess.run(
            ["airflow", "version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if re.match(r"^\d+\.\d+(\.\d+)?$", line):
                    return line
    except Exception as e:  # noqa: BLE001
        logger.debug(f"airflow subprocess version probe failed: {e}")

    return None


def get_pymisp_version() -> Optional[str]:
    """Read ``pymisp.__version__`` if installed.

    Same shape as ``get_neo4j_driver_version`` — pymisp surfaces a
    top-level ``__version__`` since 2.4.x.
    """
    try:
        import pymisp  # noqa: WPS433

        v = getattr(pymisp, "__version__", None)
        return str(v) if v else None
    except Exception as e:  # noqa: BLE001
        logger.debug(f"pymisp version capture failed: {e}")
        return None


def get_misp_server_version() -> Optional[str]:
    """Read the connected MISP server's version via ``MISPHealthCheck``.

    Reuses the existing health check rather than duplicating the API
    call — keeps a single code path for talking to MISP. Best-effort;
    returns ``None`` if MISP is unreachable, unconfigured, or the health
    check raised. ``MISPHealthCheck`` already wraps its own errors so
    this rarely fires the outer except.
    """
    try:
        from misp_health import MISPHealthCheck  # noqa: WPS433

        result = MISPHealthCheck().check_health()
        v = result.details.get("version") if hasattr(result, "details") else None
        return str(v) if v else None
    except Exception as e:  # noqa: BLE001
        logger.debug(f"MISP server version capture failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


def _parse_major_minor(version: str) -> Optional[Tuple[int, int]]:
    """Extract ``(major, minor)`` from a version string.

    Tolerant of suffixes (``5.27.0-rc1``, ``2026.03.1``, ``3.2.0+local``).
    Returns ``None`` if the string doesn't start with at least two
    dot-separated integers — caller treats that as "can't compare,
    don't warn."
    """
    if not version:
        return None
    m = _VERSION_RE.match(version.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def compare_version(component: str, running: Optional[str]) -> Tuple[str, str]:
    """Compare a single component's running version against the recommended pin.

    Returns ``(status, message)`` where status is one of:
      * ``"ok"`` — matches the major.minor pin (patch drift is fine)
      * ``"warn"`` — minor or major drift (operator needs to know)
      * ``"unknown"`` — couldn't capture the running version OR couldn't
        parse it (no pin/running comparison possible). Doctor renders
        this as info, NOT warn — silence on a missing optional dep is
        the right user experience.
    """
    recommended = RECOMMENDED_VERSIONS.get(component)
    if not recommended:
        return ("unknown", f"{component}: no recommended version registered (bug in version_compatibility?)")
    if not running:
        return ("unknown", f"{component}: running version not detected (component may not be installed/reachable)")

    rec_parsed = _parse_major_minor(recommended)
    run_parsed = _parse_major_minor(running)
    if not rec_parsed or not run_parsed:
        return ("unknown", f"{component}: cannot compare running={running!r} to recommended={recommended!r}")

    if rec_parsed == run_parsed:
        return ("ok", f"{component}: {running} matches recommended ~={recommended}")

    rec_major, rec_minor = rec_parsed
    run_major, run_minor = run_parsed
    if run_major != rec_major:
        return (
            "warn",
            f"{component}: MAJOR drift — running {running}, recommended ~={recommended}. "
            f"Likely breaking changes; verify Cypher/API call sites before deploying.",
        )
    return (
        "warn",
        f"{component}: minor drift — running {running}, recommended ~={recommended}. "
        f"Update the pin in requirements/docker-compose if this is intentional.",
    )


def compare_pinned_vs_running(
    *,
    neo4j_client_factory=None,
    misp_server_version: Optional[str] = None,
) -> List[Tuple[str, str, str]]:
    """Capture every component's running version + compare to its pin.

    Returns a list of ``(component, status, message)`` tuples in
    deterministic order. Doctor / validate iterate this list and route
    each row by status to ``ok()`` / ``warn()`` / ``info()``.

    Parameters
    ----------
    neo4j_client_factory:
        Optional factory for a Neo4j client. When provided, used by
        ``get_neo4j_server_version`` instead of constructing a fresh
        ``Neo4jClient`` (which would pay the
        ``@retry_with_backoff`` cost). Tests inject mocks here.
    misp_server_version:
        Optional pre-captured MISP server version string. When provided,
        skips the internal ``get_misp_server_version()`` call (which
        otherwise instantiates ``MISPHealthCheck`` and makes a
        round-trip to MISP).

        PR #36 commit X (bugbot LOW): ``cmd_doctor`` already calls
        ``MISPHealthCheck().check_health()`` earlier in the doctor
        flow for the MISP/PyMISP version-compat check. Without this
        parameter, ``compare_pinned_vs_running`` would do a SECOND
        round-trip via ``get_misp_server_version`` → duplicate
        network call on every doctor run. Caller passes the version
        string from the earlier call to skip the redundant probe.
    """
    captures: Dict[str, Optional[str]] = {
        "neo4j_driver": get_neo4j_driver_version(),
        "neo4j_server": get_neo4j_server_version(neo4j_client_factory=neo4j_client_factory),
        "airflow": get_airflow_version(),
        "pymisp": get_pymisp_version(),
        "misp_server": misp_server_version if misp_server_version is not None else get_misp_server_version(),
    }
    # Stable ordering for predictable output
    order = ("neo4j_server", "neo4j_driver", "airflow", "pymisp", "misp_server")
    rows = []
    for component in order:
        running = captures.get(component)
        status, message = compare_version(component, running)
        rows.append((component, status, message))
    return rows


# ---------------------------------------------------------------------------
# Pin-file source-of-truth helpers (for the regression test that pins
# RECOMMENDED_VERSIONS to actual files)
# ---------------------------------------------------------------------------


_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def read_docker_compose_neo4j_image() -> Optional[str]:
    """Extract the ``neo4j:<tag>`` image pin from ``docker-compose.yml``.

    Returns the tag portion (e.g. ``"2026.03.1-community"``) or ``None``
    if the file is missing or doesn't contain the expected line. The
    regression test uses this to verify ``RECOMMENDED_VERSIONS["neo4j_server"]``
    is a prefix of what's actually pinned in compose.
    """
    path = os.path.join(_REPO_ROOT, "docker-compose.yml")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as fh:
            for line in fh:
                stripped = line.strip()
                # Match ``image: neo4j:<tag>`` precisely — don't false-match other
                # services that happen to mention neo4j (e.g. comments, env vars)
                m = re.match(r"^image:\s*neo4j:(\S+)\s*$", stripped)
                if m:
                    return m.group(1)
    except Exception as e:  # noqa: BLE001
        logger.debug(f"docker-compose neo4j image read failed: {e}")
    return None


def read_requirements_pin(req_file: str, package: str) -> Optional[str]:
    """Extract a ``package~=N.M`` pin from a requirements file.

    ``req_file`` is a relative path under repo root (e.g.
    ``requirements.txt``). Returns the version portion after ``~=`` or
    ``None`` if not found. Used by the regression test to verify the
    Python pins match ``RECOMMENDED_VERSIONS``.
    """
    path = os.path.join(_REPO_ROOT, req_file)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as fh:
            for line in fh:
                stripped = line.strip()
                # Skip comments / blanks
                if not stripped or stripped.startswith("#"):
                    continue
                # PR #36 commit X (bugbot MED): the previous regex claimed to
                # allow "optional whitespace + extras" but never had an
                # optional bracket group, so ``apache-airflow[postgres]~=3.2``
                # silently returned None — the only RECOMMENDED_VERSIONS
                # entry without pin-file sync coverage. Now the bracketed
                # extras form (``<package>[<extras>]~=<version>``) is
                # explicitly tolerated. Extras content itself is uninspected
                # — we only care about the package name + the version pin.
                pattern = rf"^{re.escape(package)}(?:\[[^\]]*\])?\s*~=\s*([\d.]+)\s*$"
                m = re.match(pattern, stripped)
                if m:
                    return m.group(1)
    except Exception as e:  # noqa: BLE001
        logger.debug(f"requirements pin read failed for {package} in {req_file}: {e}")
    return None
