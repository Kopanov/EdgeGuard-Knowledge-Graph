#!/usr/bin/env python3
"""
Local TCP→WSS bridge so the official Neo4j **Bolt driver** can reach a
Cloudflare-fronted Neo4j that only exposes Bolt-over-WebSocket (the same
transport the Neo4j Browser uses). Direct `bolt+s://...:443` fails with
"looks like HTTP" because Cloudflare proxies HTTP/WebSocket, not raw Bolt TCP.

This opens a localhost TCP server, hands its address to a normal
`GraphDatabase.driver("bolt://127.0.0.1:<port>", encrypted=False)`, and pumps
bytes between that socket and `wss://<hostname>` as binary WebSocket frames.

Requires: websocket-client  (pip install websocket-client)

Standalone connectivity test:
  set -a; source .env.edgeguard; set +a; python scripts/neo4j_wss_bridge.py
(reads NEO4J_USER / NEO4J_PASSWORD; host defaults to neo4j-bolt.edgeguard.org,
override with NEO4J_WSS_HOST)
"""

import os
import socket
import threading

import websocket

from neo4j import GraphDatabase


class Neo4jWssBridge:
    """Local TCP-to-WSS tunnel for the neo4j driver through Cloudflare."""

    def __init__(self, hostname, auth):
        self.hostname, self.auth = hostname, auth
        self.driver, self._srv, self._stop = None, None, threading.Event()

    def connect(self):
        self._srv = socket.create_server(("127.0.0.1", 0))
        self._srv.settimeout(1)
        port = self._srv.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()
        self.driver = GraphDatabase.driver(f"bolt://127.0.0.1:{port}", auth=self.auth, encrypted=False)
        return self.driver

    def close(self):
        self._stop.set()
        if self.driver:
            self.driver.close()
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def _accept(self):
        while not self._stop.is_set():
            try:
                client, _ = self._srv.accept()
                client.settimeout(1)
                threading.Thread(target=self._bridge, args=(client,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _bridge(self, client):
        ws = websocket.create_connection(f"wss://{self.hostname}", timeout=20, enable_multithread=True)

        def pump(src, dst):
            try:
                while not self._stop.is_set():
                    try:
                        data = src()
                    except socket.timeout:
                        continue
                    if not data:
                        return
                    dst(data)
            except Exception:
                pass

        threading.Thread(
            target=pump,
            daemon=True,
            args=(lambda: client.recv(65536), lambda d: ws.send(d, opcode=websocket.ABNF.OPCODE_BINARY)),
        ).start()
        threading.Thread(
            target=pump,
            daemon=True,
            args=(ws.recv, lambda d: client.sendall(d if isinstance(d, bytes) else d.encode())),
        ).start()


if __name__ == "__main__":
    host = os.getenv("NEO4J_WSS_HOST", "neo4j-bolt.edgeguard.org")
    auth = (os.getenv("NEO4J_USER", "neo4j"), os.getenv("NEO4J_PASSWORD", ""))
    db = os.getenv("NEO4J_DATABASE", "neo4j")
    print(f"Bridging Bolt driver -> wss://{host}  (user={auth[0]}, db={db})")
    with Neo4jWssBridge(host, auth) as b:
        b.driver.verify_connectivity()
        print("Connected successfully!")
        records, _, _ = b.driver.execute_query(
            "MATCH (n) RETURN labels(n)[0] AS l, count(n) AS c ORDER BY c DESC", database_=db
        )
        for r in records:
            print(f"  {r['l']:16} {r['c']:>9,}")
