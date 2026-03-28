"""EDGEGUARD_MISP_HTTP_HOST: Host header when MISP URL netloc ≠ Apache ServerName."""

import requests


def test_apply_misp_http_host_header_set(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_HTTP_HOST", "misp-edgeguard")
    import config

    s = requests.Session()
    config.apply_misp_http_host_header(s)
    assert s.headers["Host"] == "misp-edgeguard"


def test_apply_misp_http_host_header_unset(monkeypatch):
    monkeypatch.delenv("EDGEGUARD_MISP_HTTP_HOST", raising=False)
    import config

    s = requests.Session()
    config.apply_misp_http_host_header(s)
    assert "Host" not in s.headers


def test_misp_http_headers_for_pymisp_none(monkeypatch):
    monkeypatch.delenv("EDGEGUARD_MISP_HTTP_HOST", raising=False)
    import config

    assert config.misp_http_headers_for_pymisp() is None


def test_misp_http_headers_for_pymisp_dict(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_HTTP_HOST", "vhost.example")
    import config

    assert config.misp_http_headers_for_pymisp() == {"Host": "vhost.example"}


def test_get_edgeguard_misp_http_host_strips(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_HTTP_HOST", "  foo  ")
    import config

    assert config.get_edgeguard_misp_http_host() == "foo"
