"""MISPWriter dedup treats ``<id>: <name>`` and ``<id> - <name>`` ATT&CK values as one (2026-10-21).

Until 2026-10-20 MISPWriter wrote ATT&CK techniques, tactics and tools as ``T1059.003: Windows Command
Shell``; it now writes ``T1059.003 - Windows Command Shell`` (``attack_values``). Every MISP holds
about 1,900 MITRE attributes in the colon form, and the dedup compared exact ``(type, value)``, so the
first MITRE run after the change would have pushed all of them again. The dedup keys (per event and
across events) now read a ``text`` value that parses as an ATT&CK entry in the hyphen form. A value
MISP's Import Regexp rules mangled does not parse and stays a key of its own.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from attack_values import attack_value_key
from collectors import misp_writer as mw

TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
EARLIER_EVENT = ("41", "EdgeGuard-mitre-2026-10-01")
TODAY_EVENT = ("77", f"EdgeGuard-mitre-{TODAY}")
HYPHEN = "T1059.003 - Windows Command Shell"
COLON = "T1059.003: Windows Command Shell"
MANGLED = "T1059.00%WINDIR%\\Command Shell"


# --------------------------------------------------------------------------- helper


@pytest.mark.parametrize(
    "value",
    [
        "T1059.003: Windows Command Shell",
        "T1059.003 - Windows Command Shell",
        "  T1059.003:Windows Command Shell ",
    ],
)
def test_both_forms_of_a_technique_have_one_key(value):
    assert attack_value_key(value) == HYPHEN


def test_tactic_and_tool_forms_have_one_key():
    assert attack_value_key("TA0002: Execution") == "TA0002 - Execution"
    assert attack_value_key("TA0002 - Execution") == "TA0002 - Execution"
    assert attack_value_key("S0005: Windows Credential Editor") == "S0005 - Windows Credential Editor"
    assert attack_value_key("T0807: Command-Line Interface") == "T0807 - Command-Line Interface"


@pytest.mark.parametrize(
    "value",
    [MANGLED, "T104%WINDIR%\\Management Instrumentation", "T1059", "G0007: APT28", "evil.example.com", "", None, 5],
)
def test_other_values_are_returned_unchanged(value):
    assert attack_value_key(value) == value


# --------------------------------------------------------------------------- prefetch keys


def _writer_with_rows(rows: List[dict]) -> mw.MISPWriter:
    w = mw.MISPWriter.__new__(mw.MISPWriter)
    w.url = "https://misp.test"
    w.verify_ssl = True
    w.session = MagicMock()
    response = MagicMock(status_code=200)
    response.json.return_value = {"response": {"Attribute": rows}}
    w.session.post.return_value = response
    return w


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setattr(mw, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", True)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.delenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", raising=False)
    monkeypatch.setattr(mw.time, "sleep", lambda _s: None)


def test_prefetch_keys_fold_the_colon_form_and_leave_the_rest():
    rows = [
        {"type": "text", "value": COLON},
        {"type": "text", "value": MANGLED},
        {"type": "text", "value": "plain note"},
        {"type": "comment", "value": COLON},  # not a text attribute: exact key
    ]
    expected = {("text", HYPHEN), ("text", MANGLED), ("text", "plain note"), ("comment", COLON)}
    assert _writer_with_rows(rows)._get_existing_attribute_keys("77") == expected
    assert _writer_with_rows(rows)._get_existing_source_attribute_keys("source:mitre") == expected


def test_stored_copy_lookup_still_uses_the_exact_key():
    # Stored copies are asked for by the exact key of a re-reported indicator; folding must not hide one.
    rows = [
        {"type": "text", "value": "plain note", "uuid": "u1", "timestamp": "1", "Event": {"info": EARLIER_EVENT[1]}}
    ]
    asked: Dict[Any, Any] = {("text", "plain note"): None}
    _writer_with_rows(rows)._get_existing_source_attribute_keys("source:mitre", stored_copy_of=asked)
    assert asked[("text", "plain note")] is not None


# --------------------------------------------------------------------------- push_items


class _FakeMisp:
    """MISP behind ``MISPWriter.session``: the day's event exists, ``stored`` rows are listed."""

    def __init__(self, stored: List[dict]):
        self.stored = stored

    def post(self, url: str, json: Any = None, **_kwargs: Any) -> MagicMock:
        body = json or {}
        r = MagicMock(status_code=200, text="")
        if url.endswith("/events/restSearch"):
            eid, info = TODAY_EVENT
            r.json.return_value = {"response": [{"Event": {"id": eid, "info": info}}]}
        elif url.endswith("/attributes/restSearch") and "tags" in body:
            rows = [a for a in self.stored if body["tags"][0] in [t["name"] for t in a["Tag"]]]
            r.json.return_value = {"response": {"Attribute": rows}}
        elif url.endswith("/attributes/restSearch") and "eventid" in body:
            rows = [a for a in self.stored if a["event_id"] == body["eventid"]]
            r.json.return_value = {"response": {"Attribute": rows}}
        else:  # pragma: no cover
            raise AssertionError(f"unexpected MISP request {url}")
        return r


def _technique() -> Dict[str, Any]:
    return {"type": "technique", "mitre_id": "T1059.003", "name": "Windows Command Shell", "tag": "mitre"}


def _push(monkeypatch, value: str, event: tuple, cross_event: bool = True):
    w = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    made = w.create_technique_attribute(_technique())
    assert made["value"] == HYPHEN
    tag = made["Tag"]
    eid, info = event
    row = {"id": "9", "event_id": eid, "type": "text", "value": value, "Event": {"id": eid, "info": info}, "Tag": tag}
    w.session = _FakeMisp([row])
    pushed: List[List[str]] = []

    def push_batch(event_id, batch):
        pushed.append([a["value"] for a in batch])
        return len(batch), 0

    monkeypatch.setattr(w, "_push_batch", push_batch)
    if not cross_event:
        monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", False)
    return w.push_items([_technique()]), pushed


def test_colon_value_in_an_earlier_event_skips_the_hyphen_value(monkeypatch):
    result, pushed = _push(monkeypatch, COLON, EARLIER_EVENT)
    assert result == (0, 0)
    assert pushed == []


def test_colon_value_in_the_same_event_skips_the_hyphen_value(monkeypatch):
    result, pushed = _push(monkeypatch, COLON, TODAY_EVENT, cross_event=False)
    assert result == (0, 0)
    assert pushed == []


def test_hyphen_value_already_stored_is_still_skipped(monkeypatch):
    result, pushed = _push(monkeypatch, HYPHEN, EARLIER_EVENT)
    assert result == (0, 0)
    assert pushed == []


def test_mangled_value_does_not_hide_the_clean_one(monkeypatch):
    for event, cross_event in ((EARLIER_EVENT, True), (TODAY_EVENT, False)):
        result, pushed = _push(monkeypatch, MANGLED, event, cross_event=cross_event)
        assert result == (1, 0)
        assert pushed == [[HYPHEN]]


def test_confirmation_key_stays_exact():
    # A pushed hyphen value is confirmed by itself; a colon or mangled answer is no confirmation.
    pushed = {"type": "text", "value": HYPHEN}
    assert mw._attribute_match_key(pushed) == mw._attribute_match_key({"type": "text", "value": HYPHEN})
    assert mw._attribute_match_key(pushed) != mw._attribute_match_key({"type": "text", "value": COLON})
    assert mw._attribute_match_key(pushed) != mw._attribute_match_key({"type": "text", "value": MANGLED})
