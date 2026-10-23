"""``EDGEGUARD_SSL_VERIFY`` and its ``SSL_VERIFY`` alias: one fail-closed rule for every reader (2026-10-23).

The rule: the first of ``EDGEGUARD_SSL_VERIFY`` and ``SSL_VERIFY`` that is set and not blank
decides. Its value, trimmed and case-insensitive, verifies for ``true`` / ``1`` / ``yes`` / ``on``
and does not for ``false`` / ``0`` / ``no`` / ``off``; neither variable set (or both blank) verifies;
any other value verifies and logs one WARNING naming the variable and the value.

Each reader is run with the variable set: the parser, ``config.SSL_VERIFY`` and the modules that
take it (MISP health check, health check, MISP writer and collector, MISP-to-Neo4j sync, source key
check, ``edgeguard`` and its ``validate`` check, ``scripts/clear_misp.py``), the fresh-baseline probe
and wipe, ``scripts/import_curated_package.py --push`` (in ``tests/test_curated_packages.py``) and
``scripts/preflight_baseline.sh``.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

NAMES = ("EDGEGUARD_SSL_VERIFY", "SSL_VERIFY")
VERIFY = ["true", "TRUE", " True ", "1", "yes", "YES", "on", " On\t"]
NO_VERIFY = ["false", "FALSE", " False ", "0", "no", "NO", "off", "Off\n"]
UNRECOGNISED = ["ture", "flase", "2", "-1", "enabled", "disable", "y", "n", "t", "true1"]


@pytest.fixture
def ssl_env(monkeypatch):
    """Both variables unset; the test sets what it needs."""
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _set(monkeypatch, edgeguard: Optional[str], alias: Optional[str]) -> None:
    for name, value in zip(NAMES, (edgeguard, alias), strict=True):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def _parse() -> bool:
    from config import edgeguard_ssl_verify_from_env

    return edgeguard_ssl_verify_from_env()


# --------------------------------------------------------------------------- the rule


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize(
    "value, expected",
    [(v, True) for v in VERIFY] + [(v, False) for v in NO_VERIFY] + [(v, True) for v in UNRECOGNISED],
)
def test_each_variable_is_read_by_the_rule(ssl_env, name, value, expected):
    ssl_env.setenv(name, value)
    assert _parse() is expected


@pytest.mark.parametrize("edgeguard, alias", [(None, None), ("", None), ("   ", None), (None, ""), ("", " \t ")])
def test_unset_or_blank_verifies(ssl_env, edgeguard, alias):
    _set(ssl_env, edgeguard, alias)
    assert _parse() is True


@pytest.mark.parametrize(
    "edgeguard, alias, expected",
    [
        ("true", "false", True),
        ("false", "true", False),
        ("", "false", False),
        ("  ", "0", False),
        (None, "off", False),
        (None, "1", True),
        # A set, unrecognised EDGEGUARD_SSL_VERIFY decides: it does not fall through to the alias.
        ("ture", "false", True),
    ],
)
def test_edgeguard_ssl_verify_comes_first_and_the_alias_is_read_only_when_it_is_unset_or_blank(
    ssl_env, edgeguard, alias, expected
):
    _set(ssl_env, edgeguard, alias)
    assert _parse() is expected


@pytest.mark.parametrize("name", NAMES)
def test_an_unrecognised_value_logs_one_warning_naming_the_variable_and_the_value(ssl_env, caplog, name):
    # A value no other test uses: the warning is logged once per process for each variable and value.
    value = f"verify-{uuid.uuid4().hex[:8]}"
    ssl_env.setenv(name, value)
    ssl_env.setattr(logging.getLogger("tls_verify"), "disabled", False)
    with caplog.at_level(logging.WARNING):
        assert _parse() is True
        assert _parse() is True
    records = [r for r in caplog.records if value in r.getMessage()]
    assert len(records) == 1, [r.getMessage() for r in caplog.records]
    assert records[0].levelno == logging.WARNING
    assert f"{name}=" in records[0].getMessage()
    assert "verification stays on" in records[0].getMessage()


@pytest.mark.parametrize("value", ["true", "0", "OFF", "", "  "])
def test_a_recognised_or_blank_value_logs_nothing(ssl_env, caplog, value):
    ssl_env.setenv("EDGEGUARD_SSL_VERIFY", value)
    with caplog.at_level(logging.WARNING):
        _parse()
    assert not [r for r in caplog.records if "SSL_VERIFY" in r.getMessage()]


# --------------------------------------------------------------------------- config.SSL_VERIFY and its readers

_READERS = r"""
import json, sys
from unittest.mock import MagicMock, patch

sys.path[:0] = [sys.argv[1], sys.argv[2]]
import requests

seen = {}
verify_kwargs = []


def fake_get(self, url, **kwargs):
    verify_kwargs.append(kwargs.get("verify"))
    raise requests.ConnectionError("no network in the test")


import config

seen["config.SSL_VERIFY"] = config.SSL_VERIFY
from misp_health import MISPHealthCheck

seen["misp_health"] = MISPHealthCheck(url="https://misp.invalid", api_key="k").verify_ssl
import health_check

with patch.object(requests.Session, "get", fake_get):
    health_check.health_check_misp("https://misp.invalid", "k")
seen["health_check"] = verify_kwargs.pop()
from collectors.misp_writer import MISPWriter

seen["misp_writer"] = MISPWriter(url="https://misp.invalid", api_key="k").verify_ssl
from collectors.misp_collector import MISPCollector

seen["misp_collector"] = MISPCollector().session.verify
from run_misp_to_neo4j import MISPToNeo4jSync

sync = MISPToNeo4jSync(misp_url="https://misp.invalid", misp_api_key="k", neo4j_client=MagicMock())
seen["run_misp_to_neo4j"] = sync.session.verify
import source_key_check

seen["source_key_check"] = source_key_check._ssl_verify()
import edgeguard

edgeguard._ensure_runtime_imports()
seen["edgeguard"] = edgeguard.SSL_VERIFY
seen["edgeguard validate"] = [m for m in edgeguard.check_production_issues() if "SSL" in m or "TLS" in m]
import clear_misp

clearer = clear_misp.MISPClearer(url="https://misp.invalid", api_key="k")
with patch.object(requests.Session, "get", fake_get):
    clearer.list_edgeguard_events()
seen["clear_misp"] = verify_kwargs.pop()
print("SEEN|" + json.dumps(seen))
"""

_READER_CASES: Dict[str, Optional[bool]] = {"1": True, "on": True, "off": False, "ture": True, "": True}


@pytest.fixture(scope="module")
def readers():
    """One fresh interpreter per value: ``config.SSL_VERIFY`` is read once, at import."""
    results = {}
    for value in _READER_CASES:
        env = {k: v for k, v in os.environ.items() if k not in NAMES}
        env.update(
            NEO4J_PASSWORD="x",
            MISP_API_KEY="x",
            MISP_URL="https://misp.invalid",
            EDGEGUARD_ENV="dev",
            EDGEGUARD_SSL_VERIFY=value,
        )
        done = subprocess.run(
            [sys.executable, "-c", _READERS, str(SRC), str(SCRIPTS)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert done.returncode == 0, done.stderr[-4000:]
        (line,) = [ln for ln in done.stdout.splitlines() if ln.startswith("SEEN|")]
        results[value] = (json.loads(line[len("SEEN|") :]), done.stderr)
    return results


_READER_NAMES = [
    "config.SSL_VERIFY",
    "misp_health",
    "health_check",
    "misp_writer",
    "misp_collector",
    "run_misp_to_neo4j",
    "source_key_check",
    "edgeguard",
    "clear_misp",
]


@pytest.mark.parametrize("reader", _READER_NAMES)
@pytest.mark.parametrize("value", list(_READER_CASES))
def test_every_reader_of_config_ssl_verify_follows_the_rule(readers, reader, value):
    seen, _stderr = readers[value]
    assert seen[reader] is _READER_CASES[value], f"{reader} with EDGEGUARD_SSL_VERIFY={value!r}"


@pytest.mark.parametrize("value", ["1", "on", ""])
def test_edgeguard_validate_reports_nothing_for_verification_on(readers, value):
    seen, _stderr = readers[value]
    assert seen["edgeguard validate"] == []


def test_edgeguard_validate_reports_disabled_verification(readers):
    seen, _stderr = readers["off"]
    assert len(seen["edgeguard validate"]) == 1
    assert "DISABLED" in seen["edgeguard validate"][0]


def test_edgeguard_validate_names_an_unrecognised_value_and_keeps_verification_on(readers):
    seen, stderr = readers["ture"]
    (message,) = seen["edgeguard validate"]
    assert "EDGEGUARD_SSL_VERIFY='ture'" in message and "stays on" in message
    assert "DISABLED" not in message
    # The import of config logged the warning once, though config, edgeguard and the scripts all read it.
    assert len([ln for ln in stderr.splitlines() if "'ture'" in ln]) == 1, stderr[-4000:]


# --------------------------------------------------------------------------- fresh-baseline probe and wipe


def _state(n: int = 0):
    from baseline_clean import BaselineState

    return BaselineState(
        neo4j_count=n,
        neo4j_breakdown=(),
        neo4j_ok=True,
        neo4j_error=None,
        misp_count=n,
        misp_ok=True,
        misp_error=None,
        checkpoint_count=0,
        checkpoint_ok=True,
        checkpoint_error=None,
    )


_BASELINE_CASES = [("EDGEGUARD_SSL_VERIFY", "1", True), ("EDGEGUARD_SSL_VERIFY", "ture", True)]
_BASELINE_CASES += [("EDGEGUARD_SSL_VERIFY", "off", False), ("SSL_VERIFY", "no", False), ("SSL_VERIFY", "yes", True)]


@pytest.mark.parametrize("name, value, expected", _BASELINE_CASES)
def test_the_fresh_baseline_probe_reads_tls_verification_by_the_rule(ssl_env, name, value, expected):
    import baseline_clean

    ssl_env.setenv(name, value)
    probe_misp = MagicMock(return_value=(0, None))
    with (
        patch.object(baseline_clean, "_probe_neo4j", return_value=(0, (), None)),
        patch.object(baseline_clean, "_probe_neo4j_total", return_value=0),
        patch.object(baseline_clean, "_probe_checkpoint", return_value=(0, None)),
        patch.object(baseline_clean, "_probe_misp", probe_misp),
    ):
        baseline_clean.probe_baseline_state(client=MagicMock())
    assert probe_misp.call_args.args[2] is expected


@pytest.mark.parametrize("name, value, expected", _BASELINE_CASES)
def test_the_fresh_baseline_wipe_reads_tls_verification_by_the_rule(ssl_env, name, value, expected):
    import baseline_clean

    ssl_env.setenv(name, value)
    client = MagicMock()
    client.connect.return_value = True
    wipe_misp = MagicMock(return_value=0)
    with (
        patch("neo4j_client.Neo4jClient", return_value=client),
        patch.object(baseline_clean, "_wipe_checkpoints"),
        patch.object(baseline_clean, "_wipe_neo4j"),
        patch.object(baseline_clean, "_wipe_misp_events", wipe_misp),
        patch.object(baseline_clean, "probe_baseline_state", side_effect=[_state(10), _state(0)]),
        patch.object(baseline_clean.time, "sleep"),
    ):
        baseline_clean.reset_baseline_data(
            settle_seconds=0.0, verify_timeout_seconds=10.0, verify_poll_interval_seconds=0.1
        )
    assert wipe_misp.call_args.args[2] is expected


# --------------------------------------------------------------------------- scripts/preflight_baseline.sh


def _preflight_tls_block() -> str:
    script = (SCRIPTS / "preflight_baseline.sh").read_text()
    start = script.index('hdr "[3] MISP API reachability"')
    end = script.index('if [[ -n "${MISP_URL:-}" ]] && [[ -n "${MISP_API_KEY:-}" ]]; then', start)
    return script[start:end]


def _shells():
    shells = [shutil.which("bash") or "bash"]
    # macOS ships bash 3.2 as /bin/bash, the operator workstation case the script must keep working on.
    if os.path.exists("/bin/bash") and os.path.realpath("/bin/bash") != os.path.realpath(shells[0]):
        shells.append("/bin/bash")
    return shells


def _preflight(shell: str, edgeguard: Optional[str], alias: Optional[str]):
    harness = (
        "set -uo pipefail\n"
        'pass() { echo "PASS|$*"; }\nwarn() { echo "WARN|$*"; }\nfail() { echo "FAIL|$*"; }\nhdr() { :; }\n'
        + _preflight_tls_block()
        + 'echo "FLAG|${CURL_TLS_FLAG_STR}"\n'
    )
    env = {"PATH": os.environ.get("PATH", "")}
    for name, value in zip(NAMES, (edgeguard, alias), strict=True):
        if value is not None:
            env[name] = value
    done = subprocess.run([shell, "-c", harness], env=env, capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    (flag,) = [ln[len("FLAG|") :] for ln in lines if ln.startswith("FLAG|")]
    assert flag in ("", "-k")
    return flag == "", [ln for ln in lines if not ln.startswith("FLAG|")], done.stderr


_PREFLIGHT_CASES = (
    [(v, None, True) for v in VERIFY + UNRECOGNISED]
    + [(v, None, False) for v in NO_VERIFY]
    + [(None, v, False) for v in ["false", "0", "off"]]
    + [(None, v, True) for v in ["1", "on", "ture"]]
    + [(None, None, True), ("", None, True), ("  ", "false", False), ("", "no", False)]
    + [("true", "false", True), ("false", "true", False), ("ture", "false", True)]
)


@pytest.mark.parametrize("shell", _shells())
@pytest.mark.parametrize("edgeguard, alias, expected", _PREFLIGHT_CASES)
def test_the_preflight_judges_tls_verification_as_the_services_do(ssl_env, shell, edgeguard, alias, expected):
    _set(ssl_env, edgeguard, alias)
    assert _parse() is expected
    verify, lines, stderr = _preflight(shell, edgeguard, alias)
    assert verify is expected, (edgeguard, alias, lines, stderr)
    if verify:
        assert any(ln.startswith("PASS|TLS verification enabled") for ln in lines), lines
    else:
        # The warning for disabled verification stays: MISP_API_KEY goes over unverified TLS.
        assert any(ln.startswith("WARN|TLS verification DISABLED") for ln in lines), lines


@pytest.mark.parametrize("shell", _shells())
@pytest.mark.parametrize(
    "edgeguard, alias, name, shown", [("ture", None, "EDGEGUARD_SSL_VERIFY", "ture"), (None, " 2 ", "SSL_VERIFY", "2")]
)
def test_the_preflight_warns_about_an_unrecognised_value_and_keeps_verification_on(
    shell, edgeguard, alias, name, shown
):
    verify, lines, _stderr = _preflight(shell, edgeguard, alias)
    assert verify is True
    warnings = [ln for ln in lines if ln.startswith("WARN|")]
    assert len(warnings) == 1, lines
    assert f"{name}='{shown}'" in warnings[0] and "not a recognised value" in warnings[0]


@pytest.mark.parametrize("shell", _shells())
@pytest.mark.parametrize("edgeguard, alias", [(None, None), ("true", None), ("1", None), (None, "on")])
def test_the_preflight_does_not_warn_when_verification_is_on_by_a_recognised_value_or_the_default(
    shell, edgeguard, alias
):
    verify, lines, _stderr = _preflight(shell, edgeguard, alias)
    assert verify is True
    assert not [ln for ln in lines if ln.startswith("WARN|")], lines
