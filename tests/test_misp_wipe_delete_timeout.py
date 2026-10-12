"""The MISP wipe must wait for a large event delete (2026-10-12 smoke run, finding F14)."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import baseline_clean  # noqa: E402


def test_default_read_timeout_covers_a_six_figure_attribute_event(monkeypatch):
    monkeypatch.delenv("EDGEGUARD_MISP_DELETE_TIMEOUT_SEC", raising=False)
    assert baseline_clean.misp_delete_read_timeout_sec() == 900


def test_env_override_and_garbage_fallback(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_DELETE_TIMEOUT_SEC", "120")
    assert baseline_clean.misp_delete_read_timeout_sec() == 120
    monkeypatch.setenv("EDGEGUARD_MISP_DELETE_TIMEOUT_SEC", "soon")
    assert baseline_clean.misp_delete_read_timeout_sec() == 900
    monkeypatch.setenv("EDGEGUARD_MISP_DELETE_TIMEOUT_SEC", "0")
    assert baseline_clean.misp_delete_read_timeout_sec() == 900


def test_wipe_passes_the_read_timeout_to_the_delete(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_DELETE_TIMEOUT_SEC", "777")
    sess = MagicMock()
    page = MagicMock(status_code=200)
    page.json.side_effect = [
        [{"id": "7", "info": "EdgeGuard-nvd-2026-09-14"}],
        [],
    ]
    sess.get.return_value = page
    sess.delete.return_value = MagicMock(status_code=200)
    with patch("requests.Session", return_value=sess):
        deleted = baseline_clean._wipe_misp_events("https://misp", "key", False)
    assert deleted == 1
    assert sess.delete.call_args.kwargs["timeout"] == (15, 777)
