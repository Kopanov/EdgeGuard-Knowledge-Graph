"""NEO4J_READ_TIMEOUT is configurable: the 730-day family-match link query outgrew 300 s."""

from __future__ import annotations

import importlib
import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _reload(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("EDGEGUARD_NEO4J_READ_TIMEOUT", raising=False)
    else:
        monkeypatch.setenv("EDGEGUARD_NEO4J_READ_TIMEOUT", value)
    import neo4j_client

    return importlib.reload(neo4j_client)


def test_default_leaves_room_for_the_baseline_link_queries(monkeypatch):
    try:
        assert _reload(monkeypatch, None).NEO4J_READ_TIMEOUT == 900
    finally:
        _reload(monkeypatch, None)


def test_env_override(monkeypatch):
    try:
        assert _reload(monkeypatch, "1800").NEO4J_READ_TIMEOUT == 1800
    finally:
        _reload(monkeypatch, None)
