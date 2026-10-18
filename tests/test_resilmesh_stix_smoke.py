"""``scripts/resilmesh_stix_smoke.sh`` (2026-10-18).

The script stopped at once on the macOS system bash (3.2), which has no ``mapfile``, and passed on
an empty bundle: the indicator example of ``/stix/types`` (``1.2.3.4``) is not in the graph, and the
bundle then holds only the producer identity and the extension definition. It now reads the object
types with a while-read loop, fails a bundle that holds no graph object, and exports identifiers a
baseline graph holds (APT28, T1059, CVE-2021-44228, and the newest indicator).

The script exits ``1`` on every failure, as its header and the quickstart state: a failed
``GET /stix/types`` (unreachable API, HTTP error, a body that is not the discovery JSON) ends the run
with ``1`` instead of curl's or jq's own code, and an export that answers HTTP 200 with a body that is
not JSON fails that type only, so the remaining types are still checked.

The run tests start the script against a local stub of the REST API, with every bash on the host
(``/bin/bash`` is 3.2 on macOS); they are skipped without curl or jq.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Union

import pytest

_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = _ROOT / "scripts" / "resilmesh_stix_smoke.sh"

_BASHES = sorted({p for p in (shutil.which("bash"), "/bin/bash") if p and os.path.exists(p)})

_PRODUCER = {
    "type": "identity",
    "id": "identity--00000000-0000-4000-8000-000000000001",
    "name": "EdgeGuard",
    "identity_class": "system",
    "x_edgeguard_exporter": "stix_exporter",
}
_EXTENSION = {"type": "extension-definition", "id": "extension-definition--00000000-0000-4000-8000-000000000002"}
_MARKING = {"type": "marking-definition", "id": "marking-definition--00000000-0000-4000-8000-000000000003"}
_SECTOR = {
    "type": "identity",
    "id": "identity--00000000-0000-4000-8000-000000000004",
    "name": "energy",
    "identity_class": "class",
}


def _bundle(*objects: dict) -> dict:
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-0000000000ff",
        "objects": [_PRODUCER, _EXTENSION, _MARKING, *objects],
    }


def _sdo(kind: str) -> dict:
    return {"type": kind, "id": f"{kind}--00000000-0000-4000-8000-000000000010"}


class _Api:
    """A stub of the REST API routes the script calls; records every raw request path.

    A ``bytes`` value in ``bundles`` (or ``types``) is sent as is, with HTTP 200 and ``text/html``.
    """

    def __init__(
        self,
        bundles: Dict[str, Union[dict, bytes]],
        indicator: Optional[str] = "203.0.113.7",
        types: Optional[Union[dict, bytes]] = None,
    ):
        self.bundles = bundles
        self.indicator = indicator
        self.types = types
        self.paths: List[str] = []
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep the test output clean
                pass

            def do_GET(self):
                api.paths.append(self.path)
                if self.headers.get("X-API-Key") != "test-key":
                    return self._send(401, {"detail": "unauthorized"})
                route = self.path.split("?", 1)[0]
                if route == "/stix/types":
                    if api.types is not None:
                        return self._send(200, api.types)
                    types = [{"name": n, "example": "1.2.3.4"} for n in ("indicator", "actor", "technique", "cve")]
                    return self._send(200, {"object_types": types})
                if route == "/indicators":
                    rows = [{"value": api.indicator}] if api.indicator else []
                    return self._send(200, {"indicators": rows, "total": len(rows)})
                m = re.fullmatch(r"/stix/export/([a-z]+)/(.+)", route)
                if m and m.group(1) in api.bundles:
                    return self._send(200, api.bundles[m.group(1)], "application/stix+json;version=2.1")
                return self._send(404, {"detail": "not found"})

            def _send(self, status, body, ctype="application/json"):
                if isinstance(body, bytes):
                    data, ctype = body, "text/html"
                else:
                    data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _good_bundles() -> Dict[str, dict]:
    return {
        "indicator": _bundle(_sdo("indicator")),
        "actor": _bundle(_sdo("intrusion-set")),
        "technique": _bundle(_sdo("attack-pattern")),
        "cve": _bundle(_sdo("vulnerability")),
    }


def _run(
    bash: str, api: _Api, *args: str, base: Optional[str] = None, key: str = "test-key", pretty: bool = False
) -> subprocess.CompletedProcess:
    """Runs the script against the stub; ``pretty`` keeps the default mode, which pipes the discovery
    response and each bundle through jq."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "EDGEGUARD_API_BASE": base or api.base,
        "EDGEGUARD_API_KEY": key,
    }
    argv = [bash, str(SCRIPT), *([] if pretty else ["--no-pretty"]), *args]
    return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=60)


class TestScriptText:
    @pytest.mark.parametrize("bash", _BASHES)
    def test_syntax(self, bash):
        done = subprocess.run([bash, "-n", str(SCRIPT)], capture_output=True, text=True, timeout=30)
        assert done.returncode == 0, done.stderr

    def test_no_bash4_builtins(self):
        code = [line for line in SCRIPT.read_text().splitlines() if not line.lstrip().startswith("#")]
        for builtin in ("mapfile", "readarray", "declare -A", "${var,,}"):
            assert not any(builtin in line for line in code), builtin

    def test_the_bundle_must_hold_a_graph_object(self):
        text = SCRIPT.read_text()
        assert 'or .type == "extension-definition"' in text and 'or .type == "marking-definition") | not' in text
        assert '.identity_class == "system" or has("x_edgeguard_exporter")' in text
        assert 'if [[ "$content_count" -eq 0 ]]; then' in text

    def test_defaults_exist_in_a_baseline_graph(self):
        text = SCRIPT.read_text()
        for line in ('ACTOR="APT28"', 'TECHNIQUE="T1059"', 'CVE="CVE-2021-44228"'):
            assert line in text
        assert '"$API_BASE/indicators?limit=1"' in text


@pytest.mark.skipif(not (shutil.which("curl") and shutil.which("jq")), reason="needs curl and jq")
@pytest.mark.parametrize("bash", _BASHES)
class TestScriptRuns:
    def test_passes_when_every_bundle_holds_a_graph_object(self, bash):
        api = _Api(_good_bundles())
        try:
            done = _run(bash, api)
        finally:
            api.close()
        assert done.returncode == 0, done.stdout + done.stderr
        assert "▶ all checks passed" in done.stdout
        exported = {p.split("?", 1)[0] for p in api.paths if p.startswith("/stix/export/")}
        assert exported == {
            "/stix/export/actor/APT28",
            "/stix/export/technique/T1059",
            "/stix/export/cve/CVE-2021-44228",
            "/stix/export/indicator/203.0.113.7",
        }

    def test_fails_on_a_bundle_without_a_graph_object(self, bash):
        bundles = _good_bundles()
        bundles["actor"] = _bundle()  # what an actor the graph does not hold exports
        api = _Api(bundles)
        try:
            done = _run(bash, api)
        finally:
            api.close()
        assert done.returncode == 1
        assert "actor APT28 is not in the graph" in done.stdout
        assert "▶ 1 check(s) failed" in done.stdout

    def test_a_sector_identity_counts_as_a_graph_object(self, bash):
        bundles = _good_bundles()
        bundles["cve"] = _bundle(_SECTOR)
        api = _Api(bundles)
        try:
            done = _run(bash, api)
        finally:
            api.close()
        assert done.returncode == 0, done.stdout + done.stderr

    def test_fails_when_the_graph_has_no_indicator(self, bash):
        api = _Api(_good_bundles(), indicator=None)
        try:
            done = _run(bash, api)
        finally:
            api.close()
        assert done.returncode == 1
        assert "no indicator to export" in done.stdout

    def test_flags_override_and_identifiers_are_url_encoded(self, bash):
        api = _Api(_good_bundles())
        try:
            done = _run(bash, api, "--actor", "Lazarus Group", "--indicator", "http://evil.example/a b", "--depth", "1")
        finally:
            api.close()
        assert done.returncode == 0, done.stdout + done.stderr
        exported = [p for p in api.paths if p.startswith("/stix/export/")]
        assert "/stix/export/actor/Lazarus%20Group?depth=1" in exported
        assert "/stix/export/indicator/http%3A%2F%2Fevil.example%2Fa%20b?depth=1" in exported
        assert not any(p.startswith("/indicators") for p in api.paths), "--indicator skips the lookup"

    def test_unreachable_api_exits_1_not_curls_code(self, bash):
        with socket.socket() as sock:  # a port nothing listens on once the socket is closed
            sock.bind(("127.0.0.1", 0))
            closed = f"http://127.0.0.1:{sock.getsockname()[1]}"
        api = _Api(_good_bundles())
        try:
            done = _run(bash, api, base=closed)
        finally:
            api.close()
        assert done.returncode == 1, done.stdout + done.stderr
        assert "FAIL: GET /stix/types failed" in done.stderr

    @pytest.mark.parametrize("pretty", [True, False], ids=["pretty", "no-pretty"])
    def test_discovery_http_error_exits_1(self, bash, pretty):
        api = _Api(_good_bundles())
        try:
            done = _run(bash, api, key="wrong-key", pretty=pretty)
        finally:
            api.close()
        assert done.returncode == 1, done.stdout + done.stderr
        assert "FAIL: GET /stix/types failed" in done.stderr
        assert not any(p.startswith("/stix/export/") for p in api.paths)

    @pytest.mark.parametrize("body", [b"<html>proxy error</html>", b'{"detail": "ok"}'], ids=["html", "no-types"])
    @pytest.mark.parametrize("pretty", [True, False], ids=["pretty", "no-pretty"])
    def test_discovery_body_that_is_not_the_discovery_json_exits_1(self, bash, body, pretty):
        api = _Api(_good_bundles(), types=body)
        try:
            done = _run(bash, api, pretty=pretty)
        finally:
            api.close()
        assert done.returncode == 1, done.stdout + done.stderr
        assert "FAIL: /stix/types returned no object_types" in done.stderr

    @pytest.mark.parametrize("pretty", [True, False], ids=["pretty", "no-pretty"])
    def test_a_non_json_export_fails_that_type_and_the_run_goes_on(self, bash, pretty):
        bundles: Dict[str, Union[dict, bytes]] = dict(_good_bundles())
        bundles["indicator"] = b"<html>gateway error</html>"  # the first type the stub lists
        api = _Api(bundles)
        try:
            done = _run(bash, api, pretty=pretty)
        finally:
            api.close()
        assert done.returncode == 1, done.stdout + done.stderr
        assert "✗ response is not a valid STIX bundle" in done.stdout
        assert "<html>gateway error</html>" in done.stdout
        assert "▶ 1 check(s) failed" in done.stdout
        exported = {p.split("?", 1)[0].rsplit("/", 1)[0] for p in api.paths if p.startswith("/stix/export/")}
        assert exported == {
            "/stix/export/indicator",
            "/stix/export/actor",
            "/stix/export/technique",
            "/stix/export/cve",
        }

    def test_a_bundle_whose_objects_are_not_objects_fails_that_type(self, bash):
        bundles: Dict[str, Union[dict, bytes]] = dict(_good_bundles())
        bundles["actor"] = {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-0000000000ff", "objects": ["x"]}
        api = _Api(bundles)
        try:
            done = _run(bash, api, pretty=True)
        finally:
            api.close()
        assert done.returncode == 1, done.stdout + done.stderr
        assert "✗ response is not a valid STIX bundle" in done.stdout
        assert "▶ 1 check(s) failed" in done.stdout
