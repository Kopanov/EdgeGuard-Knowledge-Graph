"""The abuse.ch Auth-Key in an export URL path never reaches a log record, at any log level.

``urllib3.connectionpool`` logs the request line of every request, path included, at DEBUG. The
v2 exports of URLhaus and MalwareBazaar carry the Auth-Key in that path
(``/v2/files/exports/<AUTH-KEY>/recent.csv``), so an operator who raises the log level to DEBUG
would find the key in the task log of every run. The download runs here against a local HTTP
server on 127.0.0.1 (no external network) with the real ``requests`` / ``urllib3`` stack.
"""

from __future__ import annotations

import http.server
import logging
import os
import sys
import threading
from typing import Iterator, List

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import collectors.collector_utils as cu  # noqa: E402
import collectors.global_feed_collector as gfc  # noqa: E402

KEY = "fakeAuthKey0123456789abcdefTESTONLY"  # an obvious fake; must never show up in a log record
BODY = b"# id,dateadded,url\n1,2026-10-24 00:00:00,http://203.0.113.7/x\n"


class _ExportHandler(http.server.BaseHTTPRequestHandler):
    paths: List[str] = []

    def do_GET(self) -> None:  # noqa: N802 (http.server's method name)
        type(self).paths.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args: object) -> None:
        """The test server's own access log (stderr) is not under test."""


@pytest.fixture
def export_server() -> Iterator[str]:
    _ExportHandler.paths = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _ExportHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_debug_logging_of_the_http_library_never_shows_the_key(export_server, caplog) -> None:
    url = f"{export_server}/v2/files/exports/{KEY}/recent.csv"
    with caplog.at_level(logging.DEBUG), caplog.at_level(logging.DEBUG, logger="urllib3.connectionpool"):
        response = gfc.download_abusech_export(url, KEY, context="test", timeout=(5, 5))

    assert response.status_code == 200 and response.content == BODY, "the download itself still succeeds"
    assert _ExportHandler.paths == [f"/v2/files/exports/{KEY}/recent.csv"], "the server received the real key"
    assert all(KEY not in record.getMessage() for record in caplog.records)
    assert KEY not in caplog.text
    request_lines = [record for record in caplog.records if record.name == "urllib3.connectionpool"]
    assert any('"GET /v2/files/exports/<redacted>/recent.csv' in record.getMessage() for record in request_lines), (
        "urllib3 logged the request line at DEBUG, with the key redacted"
    )


def test_the_filter_is_installed_once_and_leaves_other_records_alone() -> None:
    cu.install_export_key_log_filter()
    cu.install_export_key_log_filter()
    pool = logging.getLogger("urllib3.connectionpool")
    marked = [f for f in pool.filters if getattr(f, "edgeguard_export_key_filter", False)]
    assert len(marked) == 1, "installing again adds no second filter"

    (key_filter,) = marked
    other = logging.LogRecord(
        "urllib3.connectionpool", logging.DEBUG, __file__, 1, '%s "%s %s" %s', ("h", "GET", "/api/v1/", 200), None
    )
    assert key_filter.filter(other) is True
    assert other.args == ("h", "GET", "/api/v1/", 200) and other.getMessage() == 'h "GET /api/v1/" 200'

    secret = logging.LogRecord(
        "urllib3.connectionpool", logging.DEBUG, __file__, 1, '"%s %s"', ("GET", f"/v2/files/exports/{KEY}/x"), None
    )
    assert key_filter.filter(secret) is True, "the record is kept, only redacted"
    assert secret.getMessage() == '"GET /v2/files/exports/<redacted>/x"'
