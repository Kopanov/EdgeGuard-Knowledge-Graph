"""The Neo4j driver asks the server not to send DEPRECATION notifications.

Neo4j 2026.x flags ``apoc.coll.toSet`` / ``apoc.coll.sort`` as deprecated. The Python driver logs
every notification at WARNING with the full query text, so a sync that runs the same MERGE a few
hundred thousand times wrote a 5.4 GB task log, and Airflow's log directory grew past 30 GB.
The client disables that category when it creates the driver; other categories still arrive.
"""

from __future__ import annotations

import os
import sys

from neo4j import NotificationDisabledCategory

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from test_neo4j_transaction_timeout import _RecordingDriver  # noqa: E402

import neo4j_client as nc  # noqa: E402


def _connect(monkeypatch):
    seen = {}

    def fake_driver(*args, **kwargs):
        seen.update(kwargs)
        return _RecordingDriver()

    monkeypatch.setattr(nc.GraphDatabase, "driver", fake_driver)
    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.uri, client.user, client.password = "bolt://x:7687", "neo4j", "pw"
    client.driver = None
    client._connection_healthy = False
    assert client.connect() is True
    return seen


def test_driver_disables_deprecation_notifications(monkeypatch):
    seen = _connect(monkeypatch)
    assert list(seen["notifications_disabled_categories"]) == [NotificationDisabledCategory.DEPRECATION]


def test_other_notification_categories_stay_enabled(monkeypatch):
    seen = _connect(monkeypatch)
    assert "notifications_min_severity" not in seen
