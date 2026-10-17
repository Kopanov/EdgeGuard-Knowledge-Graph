"""A minimal Bolt 5.2 server for driving the real neo4j Python driver in tests (2026-10).

A Neo4j server answers ``RUN`` once it has accepted a statement and reports an error it meets while
the statement executes or commits (a deadlock, a lock or transaction timeout, a constraint
violation, a value it cannot convert) in its answer to the ``PULL`` (or ``DISCARD``) that reads the
result. A mocked session cannot show what the driver does with such an error, so the tests that need
it run the driver against this server: it accepts every ``RUN`` and answers the ``PULL`` of a chosen
statement with a scripted ``FAILURE``, every other one with ``SUCCESS`` and write counters.

Only what the tests need is implemented: HELLO, LOGON, RESET, GOODBYE, RUN, PULL and DISCARD;
BEGIN, COMMIT, ROLLBACK and TELEMETRY are answered with ``SUCCESS``. No statement returns records
except the client's ``RETURN 1 as test`` health check. It uses the driver's own PackStream codec
(a private module of the pinned ``neo4j~=5.27``), so a driver upgrade that moves it fails here first.
"""

from __future__ import annotations

import re
import socket
import struct
import threading
from typing import Dict, List, Optional

from neo4j._codec.packstream.v1 import PackableBuffer, Packer, UnpackableBuffer, Unpacker

SUCCESS, RECORD, FAILURE = b"\x70", b"\x71", b"\x7f"


def _pack(tag: bytes, fields: list) -> bytes:
    buf = PackableBuffer()
    Packer(buf).pack_struct(tag, fields)
    data = bytes(buf.data)
    out = bytearray()
    for i in range(0, len(data), 0xFFFF):
        chunk = data[i : i + 0xFFFF]
        out += struct.pack(">H", len(chunk)) + chunk
    out += b"\x00\x00"
    return bytes(out)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise ConnectionError("closed")
        data += part
    return data


def _read_message(sock: socket.socket):
    data = b""
    while True:
        (size,) = struct.unpack(">H", _recv_exact(sock, 2))
        if size == 0:
            if data:
                break
            continue  # NOOP chunk
        data += _recv_exact(sock, size)
    unpacker = Unpacker(UnpackableBuffer(data))
    size, tag = unpacker.unpack_structure_header()
    fields = [unpacker.unpack() for _ in range(size)]
    return tag, fields


class FakeBolt:
    """A Bolt server on a free local port.

    ``fail_rules``: dicts ``{"match": callable(query) -> bool, "code": str, "message": str,
    "times": int}``; the first rule that matches a statement and has ``times`` left answers that
    statement's ``PULL``/``DISCARD`` with ``FAILURE`` (``code``, ``message``) and uses up one time.
    A rule with ``"drop": True`` closes the connection instead, as a network failure would.
    ``runs`` holds every statement received, in order, and ``parameters`` the parameters of each, as
    the driver packed them; ``failures`` and ``committed`` the statements whose result was answered with
    ``FAILURE`` and with ``SUCCESS``.
    """

    def __init__(self, fail_rules: Optional[List[Dict]] = None):
        self.fail_rules = fail_rules or []
        self.runs: List[str] = []
        self.parameters: List[Dict] = []
        self.failures: List[str] = []
        self.committed: List[str] = []
        self._lock = threading.Lock()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._accept_loop, daemon=True).start()

    @property
    def uri(self) -> str:
        return f"bolt://127.0.0.1:{self.port}"

    def close(self) -> None:
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass

    def _accept_loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _rule_for(self, query: str) -> Optional[Dict]:
        with self._lock:
            for rule in self.fail_rules:
                if rule.get("times", 1) > 0 and rule["match"](query):
                    rule["times"] = rule.get("times", 1) - 1
                    return rule
        return None

    @staticmethod
    def _fields_for(query: str) -> List[str]:
        idx = query.upper().rfind("RETURN")
        if idx < 0:
            return []
        return re.findall(r"\b[Aa][Ss]\s+(\w+)", query[idx:])

    def _serve(self, conn: socket.socket) -> None:
        try:
            _recv_exact(conn, 4)  # magic preamble
            _recv_exact(conn, 16)  # version proposals
            conn.sendall(b"\x00\x00\x02\x05")  # Bolt 5.2: the client's notification filter is accepted
            last_query = None
            while True:
                tag, fields = _read_message(conn)
                if tag == b"\x01":  # HELLO
                    conn.sendall(_pack(SUCCESS, [{"server": "Neo4j/5.26.0", "connection_id": "bolt-1"}]))
                elif tag in (b"\x6a", b"\x0f"):  # LOGON, RESET
                    conn.sendall(_pack(SUCCESS, [{}]))
                elif tag == b"\x02":  # GOODBYE
                    return
                elif tag == b"\x10":  # RUN
                    last_query = fields[0]
                    with self._lock:
                        self.runs.append(last_query)
                        self.parameters.append(fields[1] if len(fields) > 1 else {})
                    conn.sendall(_pack(SUCCESS, [{"fields": self._fields_for(last_query), "t_first": 1}]))
                elif tag in (b"\x3f", b"\x2f"):  # PULL, DISCARD
                    rule = self._rule_for(last_query or "")
                    if rule is not None:
                        with self._lock:
                            self.failures.append(last_query or "")
                        if rule.get("drop"):  # the connection is lost while the statement runs
                            return
                        conn.sendall(_pack(FAILURE, [{"code": rule["code"], "message": rule["message"]}]))
                        continue
                    with self._lock:
                        self.committed.append(last_query or "")
                    out = b""
                    if last_query and "RETURN 1 as test" in last_query and tag == b"\x3f":
                        out += _pack(RECORD, [[1]])
                    stats = {"nodes-created": 1, "properties-set": 5, "relationships-created": 1}
                    out += _pack(
                        SUCCESS, [{"has_more": False, "type": "w", "t_last": 1, "db": "neo4j", "stats": stats}]
                    )
                    conn.sendall(out)
                else:  # BEGIN, COMMIT, ROLLBACK, TELEMETRY, ...
                    conn.sendall(_pack(SUCCESS, [{}]))
        except (ConnectionError, OSError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass


def fail(substring: str, code: str = "", times: int = 1, drop: bool = False) -> Dict:
    """A rule failing the result of the next ``times`` statements that contain ``substring`` (with
    ``drop``, by closing the connection)."""
    return {
        "match": lambda q: substring in q,
        "code": code,
        "message": "scripted failure",
        "times": times,
        "drop": drop,
    }


def count(statements: List[str], substring: str) -> int:
    """How many of ``statements`` contain ``substring``."""
    return sum(1 for q in statements if substring in q)
