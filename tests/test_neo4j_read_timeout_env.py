"""NEO4J_READ_TIMEOUT is configurable: the 730-day family-match link query outgrew 300 s.

The module constant is read in a child interpreter: reloading ``neo4j_client`` in this
process would replace its classes and break ``isinstance`` checks in later test modules.
"""

from __future__ import annotations

import os
import subprocess
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")


def _timeout(value):
    env = {k: v for k, v in os.environ.items() if k != "EDGEGUARD_NEO4J_READ_TIMEOUT"}
    if value is not None:
        env["EDGEGUARD_NEO4J_READ_TIMEOUT"] = value
    out = subprocess.run(
        [sys.executable, "-c", "import neo4j_client; print(neo4j_client.NEO4J_READ_TIMEOUT)"],
        cwd=_SRC,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return int(out.stdout.strip().splitlines()[-1])


def test_default_leaves_room_for_the_baseline_link_queries():
    assert _timeout(None) == 1200


def test_env_override():
    assert _timeout("1800") == 1800
