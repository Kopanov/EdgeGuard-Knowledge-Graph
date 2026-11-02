"""The dedup within one MISP push compares attributes as the push confirmation does (2026-11).

``MISPWriter.push_items`` dropped a second attribute of a (source, date) group only when its type and
value were exactly those of an earlier one. MISP trims values and changes the case of some types on save
(hashes, domains, host names, IP and e-mail addresses, CVE ids: ``_CASE_NORMALISED_TYPES``), so two
attributes that differ only so are one value in MISP: the second was pushed and MISP stored it once. The
dedup now keys on ``_attribute_match_key``, the rule the push confirmation uses: such a variant is not
pushed and is logged (``[CASE-VARIANT]``), because its comment and tags are not merged into the attribute
pushed. Types MISP stores as given (malware and threat-actor names, URLs, text) stay case-exact here; the
OTX collector folds its own name and URL variants before the push
(``tests/test_otx_case_variant_fold.py``).

Values: a real SHA-256 and a real domain of the OTX event of 2026-11-01 and the real ``DcRat`` /
``DCRAT`` spellings of that run.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from collectors import misp_writer as mw

TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
SHA256 = "09bedbf7a41e0f8dabe4f41d331db58373ce15b2e9204540873a1884f38bdde1"
DOMAIN = "gatuso.duckdns.org"


class _FakeMisp:
    """MISP 2.5 answering the requests ``push_items`` sends before a batch: no event yet, nothing stored."""

    def __init__(self):
        self.events: Dict[str, str] = {}

    def post(self, url: str, json: Optional[dict] = None, **_kwargs: Any) -> MagicMock:
        body = json or {}
        r = MagicMock()
        r.status_code = 200
        r.text = ""
        if url.endswith("/events/restSearch"):
            eid = self.events.get(body["eventinfo"])
            r.json.return_value = {"response": [{"Event": {"id": eid, "info": body["eventinfo"]}}] if eid else []}
        elif url.endswith("/events"):
            eid = str(100 + len(self.events))
            self.events[body["Event"]["info"]] = eid
            r.json.return_value = {"Event": {"id": eid, "info": body["Event"]["info"]}}
        elif url.endswith("/attributes/restSearch"):
            r.json.return_value = {"response": {"Attribute": []}}
        else:  # pragma: no cover - a request the writer must not send here
            raise AssertionError(f"unexpected MISP request {url}")
        return r


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setattr(mw, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", True)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.delenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", raising=False)
    monkeypatch.setattr(mw.time, "sleep", lambda _s: None)


def _writer(monkeypatch, fail: bool = False):
    writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    writer.session = _FakeMisp()
    pushed: List[List[tuple]] = []

    def push_batch(_event_id, batch):
        pushed.append([(a["type"], a["value"]) for a in batch])
        return (0, len(batch)) if fail else (len(batch), 0)

    monkeypatch.setattr(writer, "_push_batch", push_batch)
    return writer, pushed


def _ioc(indicator_type: str, value: str, tag: str = "threatfox", **extra) -> Dict[str, Any]:
    return {"indicator_type": indicator_type, "value": value, "zone": ["global"], "tag": tag, "source": [tag], **extra}


def _variant_lines(caplog) -> List[str]:
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("[CASE-VARIANT]")]


def test_a_hash_in_two_cases_is_pushed_once_and_the_variant_logged(monkeypatch, caplog):
    writer, pushed = _writer(monkeypatch)
    items = [_ioc("hash", SHA256), _ioc("hash", SHA256.upper())]
    with caplog.at_level(logging.WARNING, logger=mw.logger.name):
        assert writer.push_items(items) == (1, 0)
    assert pushed == [[("sha256", SHA256)]], "the first spelling is pushed"
    lines = _variant_lines(caplog)
    assert len(lines) == 1 and f"sha256 {SHA256.upper()!r} (pushed: {SHA256!r})" in lines[0]
    assert lines[0].startswith(f"[CASE-VARIANT] MISP push threatfox ({TODAY}): 1 attribute(s) not pushed")


def test_a_domain_differing_in_case_and_whitespace_is_pushed_once(monkeypatch, caplog):
    writer, pushed = _writer(monkeypatch)
    with caplog.at_level(logging.WARNING, logger=mw.logger.name):
        assert writer.push_items([_ioc("domain", "Gatuso.DuckDNS.org"), _ioc("domain", f" {DOMAIN} ")]) == (1, 0)
    assert pushed == [[("domain", "Gatuso.DuckDNS.org")]]
    assert len(_variant_lines(caplog)) == 1


def test_an_exact_duplicate_is_dropped_without_a_variant_line(monkeypatch, caplog):
    writer, pushed = _writer(monkeypatch)
    with caplog.at_level(logging.WARNING, logger=mw.logger.name):
        assert writer.push_items([_ioc("domain", DOMAIN), _ioc("domain", DOMAIN)]) == (1, 0)
    assert pushed == [[("domain", DOMAIN)]]
    assert _variant_lines(caplog) == []


@pytest.mark.parametrize(
    "items, expected",
    [
        (
            [
                {"type": "malware", "name": "DcRat", "tag": "threatfox", "zone": ["global"]},
                {"type": "malware", "name": "DCRAT", "tag": "threatfox", "zone": ["global"]},
            ],
            [("malware-type", "DcRat"), ("malware-type", "DCRAT")],
        ),
        (
            [_ioc("url", "http://twizt.net/Installed"), _ioc("url", "http://twizt.net/installed")],
            [("url", "http://twizt.net/Installed"), ("url", "http://twizt.net/installed")],
        ),
    ],
    ids=["malware names", "urls"],
)
def test_types_misp_stores_as_given_are_compared_exactly(monkeypatch, caplog, items, expected):
    writer, pushed = _writer(monkeypatch)
    with caplog.at_level(logging.WARNING, logger=mw.logger.name):
        assert writer.push_items(items) == (2, 0)
    assert pushed == [expected]
    assert _variant_lines(caplog) == []


def test_the_items_of_a_dropped_variant_are_unstored_with_the_attribute_pushed(monkeypatch):
    """A failed batch lists its items as unstored (the OTX cursor reads them): a variant's item with them."""
    writer, pushed = _writer(monkeypatch, fail=True)
    items = [
        _ioc("domain", "other.example"),
        _ioc("hash", SHA256),
        _ioc("domain", "Gatuso.DuckDNS.org"),
        _ioc("hash", SHA256.upper()),
        _ioc("domain", DOMAIN),
    ]
    assert writer.push_items(items) == (0, 3)
    assert pushed == [[("domain", "other.example"), ("sha256", SHA256), ("domain", "Gatuso.DuckDNS.org")]]
    assert writer.last_push_unstored_items == [0, 1, 2, 3, 4]


def test_the_variants_of_a_large_push_are_counted_and_sampled(monkeypatch, caplog):
    writer, pushed = _writer(monkeypatch)
    digests = [f"{n:x}" * 64 for n in range(10, 16)] + ["ab" * 32]  # aaaa…, bbbb…, …, ffff…, abab…
    items = [_ioc("hash", d) for d in digests] + [_ioc("hash", d.upper()) for d in digests]
    with caplog.at_level(logging.WARNING, logger=mw.logger.name):
        assert writer.push_items(items) == (7, 0)
    assert pushed == [[("sha256", d) for d in digests]]
    lines = _variant_lines(caplog)
    assert len(lines) == 1 and ": 7 attribute(s) not pushed" in lines[0]
    assert f"(first {mw._CASE_VARIANT_LOG_SAMPLE}: " in lines[0]
    assert lines[0].count("(pushed: ") == mw._CASE_VARIANT_LOG_SAMPLE == 5


@pytest.mark.parametrize(
    "attribute, key",
    [
        ({"type": "sha256", "value": SHA256.upper()}, ("sha256", SHA256)),
        ({"type": "Domain", "value": " Gatuso.DuckDNS.org "}, ("domain", DOMAIN)),
        ({"type": "malware-type", "value": "DCRAT"}, ("malware-type", "DCRAT")),
        ({"type": "url", "value": "http://Setseta.com/set.exe"}, ("url", "http://Setseta.com/set.exe")),
        ({"type": "text", "value": None}, ("text", "None")),
        ({"type": "text", "value": "   "}, ("text", "   ")),
        ({"value": "x"}, ("None", "x")),
        ("not a dict", ("", "not a dict")),
    ],
)
def test_the_key_is_the_confirmation_key_or_the_exact_pair(attribute, key):
    assert mw._within_push_key(attribute) == key
    if mw._attribute_match_key(attribute) is not None:
        assert mw._within_push_key(attribute) == mw._attribute_match_key(attribute)
