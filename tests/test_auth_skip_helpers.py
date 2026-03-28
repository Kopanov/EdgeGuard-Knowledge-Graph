"""is_auth_or_access_denied + ThreatFox optional skip (no key / 401)."""

from unittest.mock import MagicMock, patch

import requests

from collectors.collector_utils import is_auth_or_access_denied


def test_is_auth_http_error_with_response_401():
    r = MagicMock()
    r.status_code = 401
    e = requests.HTTPError("401")
    e.response = r
    assert is_auth_or_access_denied(e) is True


def test_is_auth_http_error_with_response_403():
    r = MagicMock()
    r.status_code = 403
    e = requests.HTTPError("nope")
    e.response = r
    assert is_auth_or_access_denied(e) is True


def test_is_auth_message_invalid_api_key():
    assert is_auth_or_access_denied(Exception("Invalid VirusTotal API key")) is True


def test_threatfox_skips_when_no_api_key_push_to_misp():
    from collectors.global_feed_collector import ThreatFoxCollector

    c = ThreatFoxCollector(api_key=None, misp_writer=MagicMock())
    c.api_key = None
    out = c.collect(limit=10, push_to_misp=True, baseline=False)
    assert out["success"] is True
    assert out.get("skipped") is True
    assert out.get("skip_reason_class") == "missing_threatfox_key"


def test_threatfox_skips_on_401_from_api():
    from collectors.global_feed_collector import ThreatFoxCollector

    c = ThreatFoxCollector(api_key="real-looking-key", misp_writer=MagicMock())

    resp = MagicMock()
    resp.status_code = 401
    err = requests.HTTPError(response=resp)

    with patch.object(ThreatFoxCollector, "_fetch_iocs", side_effect=err):
        out = c.collect(limit=10, push_to_misp=True, baseline=False)

    assert out["success"] is True
    assert out.get("skipped") is True
    assert out.get("skip_reason_class") == "threatfox_auth_denied"
