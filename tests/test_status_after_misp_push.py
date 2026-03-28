"""Tests for collector_utils.status_after_misp_push."""

from collectors.collector_utils import status_after_misp_push


def test_empty_batch_success():
    st = status_after_misp_push("otx", 0, 0, 0)
    assert st["success"] is True
    assert st["count"] == 0
    assert st["failed"] == 0


def test_all_failed():
    st = status_after_misp_push("otx", 10, 0, 10)
    assert st["success"] is False
    assert st["count"] == 10
    assert st["failed"] == 10
    assert "failures" in st["error"]


def test_partial_success():
    st = status_after_misp_push("otx", 10, 3, 2)
    assert st["success"] is True
    assert st["count"] == 10
    assert st["failed"] == 2
