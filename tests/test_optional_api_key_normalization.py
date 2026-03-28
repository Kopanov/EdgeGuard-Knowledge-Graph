"""optional_api_key_effective() — strip, whitespace, YAML placeholders."""

from collectors.collector_utils import (
    ABUSEIPDB_API_KEY_PLACEHOLDERS,
    OTX_API_KEY_PLACEHOLDERS,
    VIRUSTOTAL_API_KEY_PLACEHOLDERS,
    optional_api_key_effective,
)


def test_strips_and_returns_real_key():
    assert optional_api_key_effective("  abc  ", frozenset()) == "abc"


def test_empty_and_whitespace_are_none():
    assert optional_api_key_effective(None, VIRUSTOTAL_API_KEY_PLACEHOLDERS) is None
    assert optional_api_key_effective("", VIRUSTOTAL_API_KEY_PLACEHOLDERS) is None
    assert optional_api_key_effective("  \t\n", VIRUSTOTAL_API_KEY_PLACEHOLDERS) is None


def test_virustotal_yaml_placeholders():
    assert optional_api_key_effective("YOUR_VT_API_KEY", VIRUSTOTAL_API_KEY_PLACEHOLDERS) is None
    assert optional_api_key_effective("YOUR_VIRUSTOTAL_API_KEY_HERE", VIRUSTOTAL_API_KEY_PLACEHOLDERS) is None


def test_otx_yaml_placeholder():
    assert optional_api_key_effective("YOUR_OTX_API_KEY_HERE", OTX_API_KEY_PLACEHOLDERS) is None


def test_abuseipdb_yaml_placeholder():
    assert optional_api_key_effective("YOUR_ABUSEIPDB_API_KEY_HERE", ABUSEIPDB_API_KEY_PLACEHOLDERS) is None
