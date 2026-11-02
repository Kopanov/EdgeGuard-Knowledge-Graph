"""The identity of a ``url`` Indicator: scheme and host lower-cased, the path as given (2026-11).

RFC 3986 makes a URL's scheme and host case-insensitive and leaves the case of the rest to the server.
The ``url`` key kept the whole value as given, so OTX pulse ``5d8dcf197ec3aea4d3e338df``, which lists
``http://setseta.com/set.exe`` and ``http://Setseta.com/set.exe``, gave two Indicator nodes sharing one
uuid (the uuid hashes the lower-cased key). ``node_identity.fold_url_scheme_and_host`` now lower-cases
the scheme and the host of a ``url`` key on write (``canonicalize_merge_key``) and of a ``url`` lookup
on read (``ioc_normalize.normalize_indicator_value``), as well as of any ``scheme://host`` value a lookup
gets without a type (the lookup infers url only for http, https and ftp); a path differing in case stays
another URL.

The 730-day graph of 2026-11-01 holds 36 url values whose scheme or host has upper case (35 OTX, one
URLhaus); 5 of them have a lower-case twin. ``LIVE_UPPER_CASE_HOSTS`` are real values among them. Every
Indicator caller of ``canonicalize_merge_key`` is run here with a mocked driver;
``tests/test_url_identity_neo4j.py`` runs them on a real Neo4j.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from ioc_normalize import canonicalize_lookup, infer_indicator_type, normalize_indicator_value, refang  # noqa: E402
from node_identity import canonicalize_merge_key, compute_node_uuid, fold_url_scheme_and_host  # noqa: E402

# Real values of the 730-day graph (2026-11-01) with upper case in the scheme or host, and their keys.
LIVE_UPPER_CASE_HOSTS = {
    "http://Setseta.com/set.exe": "http://setseta.com/set.exe",
    "http://D3f4.com.hk/OfJ3qDlVoGBRGjYK/conf.php": "http://d3f4.com.hk/OfJ3qDlVoGBRGjYK/conf.php",
    "http://Kaiwachis.ug/NShnObEA4XwtlDCC/gate.php": "http://kaiwachis.ug/NShnObEA4XwtlDCC/gate.php",
    "http://Chujwdupepolicji123-40502.portmap.host:40502": "http://chujwdupepolicji123-40502.portmap.host:40502",
    "http://LsyPdQGXrEDfPx.MSwInSofTUpDloAd.dESign/111111?sub=s": "http://lsypdqgxredfpx.mswinsoftupdload.design/111111?sub=s",
    "http://iNVsetmX.cOM/ipa.AsPX\\": "http://invsetmx.com/ipa.AsPX\\",
    "https://MTID.ubiqauitous1.com/B9Z64HC_oJbkvSmVBaQzfkiG7YNd-0Po/#Y2xpY29uQGNlbH": (
        "https://mtid.ubiqauitous1.com/B9Z64HC_oJbkvSmVBaQzfkiG7YNd-0Po/#Y2xpY29uQGNlbH"
    ),
    "https://3D4EBF0-54a1-4844-bD7a-709370159964.selectivewilled.cc/install.ps1": (
        "https://3d4ebf0-54a1-4844-bd7a-709370159964.selectivewilled.cc/install.ps1"
    ),
    "https://googIedrivers.com/fix-error": "https://googiedrivers.com/fix-error",
}

# Values the fold must leave as given: (value, why).
UNCHANGED = [
    ("http://setseta.com/set.exe", "already lower case"),
    ("http://twizt.net/Installed", "only the path has upper case"),
    ("Setseta.COM/set.exe", "no scheme"),
    ("//Setseta.COM/set.exe", "no scheme"),
    ("mailto:Admin@Example.org", "no authority"),
    ("hxxp://Setseta.COM/set.exe", "defanged scheme"),
    ("HXXPS://Setseta.COM/set.exe", "defanged scheme"),
    ("http://Setseta[.]COM/set.exe", "defanged host"),
    ("http://Setseta(.)COM/set.exe", "defanged host"),
    ("http://Setseta{.}COM/set.exe", "defanged host"),
    ("http://User[@]Setseta.COM/", "defanged at-sign"),
    ("http://Set%53eta.COM/", "percent-encoded host"),
    ("http://[FE80::1%25ETH0]/X", "IPv6 zone id"),
    ("http://Setseta.COM:http/X", "port not a number"),
    ("http://Setseta.COM:80:90/X", "two ports"),
    ("http://Evil.COM\\Path", "a backslash in the host"),
    ("http:// Evil.COM/", "whitespace in the host"),
    ("1http://Evil.COM/", "a scheme starts with a letter"),
    ("", "empty"),
]

FOLDED = [
    ("HTTP://Setseta.COM/Set.exe?A=B#C", "http://setseta.com/Set.exe?A=B#C"),
    ("http://Setseta.COM:8080/X", "http://setseta.com:8080/X"),
    ("http://Setseta.COM:/X", "http://setseta.com:/X"),
    ("https://User:PassWord@Setseta.COM/X", "https://User:PassWord@setseta.com/X"),
    ("http://Me@Mail.Example@Evil.COM/X", "http://Me@Mail.Example@evil.com/X"),  # the host follows the last @
    ("http://[2001:DB8::1]:8443/X", "http://[2001:db8::1]:8443/X"),
    ("http://198.51.100.7/Mozi.m", "http://198.51.100.7/Mozi.m"),
    ("http://München.DE/Pfad", "http://münchen.de/Pfad"),
    ("FTP://Files.Example.ORG", "ftp://files.example.org"),
    ("http://Setseta.COM?Q=1", "http://setseta.com?Q=1"),
    ("http://Setseta.COM#Frag", "http://setseta.com#Frag"),
    ("http://Setseta.COM./X", "http://setseta.com./X"),
    ("FILE:///C:/Windows/X.EXE", "file:///C:/Windows/X.EXE"),
    ("https://bashupload.com/uCiPm/SENT_Kill[.]zip", "https://bashupload.com/uCiPm/SENT_Kill[.]zip"),
    ("http://Evil.COM/A\nB", "http://evil.com/A\nB"),
]


# --------------------------------------------------------------------------- fold_url_scheme_and_host


@pytest.mark.parametrize("value, key", sorted(LIVE_UPPER_CASE_HOSTS.items()))
def test_live_values_get_a_lower_case_scheme_and_host(value, key):
    assert fold_url_scheme_and_host(value) == key


@pytest.mark.parametrize("value, why", UNCHANGED, ids=[w for _v, w in UNCHANGED])
def test_values_that_are_not_a_plain_url_stay_as_given(value, why):
    assert fold_url_scheme_and_host(value) == value


@pytest.mark.parametrize("value, key", FOLDED)
def test_scheme_and_host_fold_and_the_rest_keeps_its_case(value, key):
    assert fold_url_scheme_and_host(value) == key


@pytest.mark.parametrize("value", [None, 7, 3.5, b"HTTP://X.COM/", ["http://X.COM"], {"v": 1}])
def test_a_non_string_is_returned_unchanged(value):
    assert fold_url_scheme_and_host(value) is value


def test_never_raises_changes_only_case_and_is_idempotent():
    alphabet = "hHtTpPsS:/.?#@[]()%{}\\ \t\n-_~!$&'*+,;=0123456789aAzZéÉ|"
    rng = random.Random(20261102)
    for _ in range(20000):
        value = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        if rng.random() < 0.5:
            value = rng.choice(["http://", "HTTPS://", "Ftp://", "hxxp://"]) + value
        out = fold_url_scheme_and_host(value)
        assert isinstance(out, str) and out.lower() == value.lower() and len(out) == len(value)
        assert fold_url_scheme_and_host(out) == out


def test_a_very_long_value_is_folded_in_linear_time():
    value = "http://Evil.COM/" + "A" * 2_000_000
    assert fold_url_scheme_and_host(value) == "http://evil.com/" + "A" * 2_000_000


# --------------------------------------------------------------------------- the write key and the uuid


def _key(value: str) -> str:
    return canonicalize_merge_key("Indicator", {"indicator_type": "url", "value": value})["value"]


def test_the_two_spellings_of_one_url_get_one_key_and_one_uuid():
    a, b = "http://Setseta.com/set.exe", "http://setseta.com/set.exe"
    assert _key(a) == _key(b) == b
    assert compute_node_uuid("Indicator", {"indicator_type": "url", "value": _key(a)}) == compute_node_uuid(
        "Indicator", {"indicator_type": "url", "value": a}
    ), "the uuid of the node follows its key"


def test_urls_whose_paths_differ_in_case_keep_two_keys():
    assert _key("http://twizt.net/Installed") != _key("http://twizt.net/installed")


def test_the_key_strips_and_nfc_normalises_before_folding():
    assert _key("  HTTP://Me\u0301xico.COM/Á  ") == "http://m\u00e9xico.com/Á"


@pytest.mark.parametrize("indicator_type", ["url", "URL", "Url"])
def test_the_type_is_read_without_case(indicator_type):
    out = canonicalize_merge_key("Indicator", {"indicator_type": indicator_type, "value": "http://Setseta.com/X"})
    assert out == {"indicator_type": indicator_type, "value": "http://setseta.com/X"}


@pytest.mark.parametrize(
    "indicator_type, value",
    [("filename", "Invoice.EXE"), ("email", "Admin@Example.org"), ("unknown", "HTTP://Setseta.COM/X")],
)
def test_other_case_sensitive_types_are_untouched(indicator_type, value):
    assert canonicalize_merge_key("Indicator", {"indicator_type": indicator_type, "value": value})["value"] == value


def test_names_of_other_labels_are_untouched_by_the_url_rule():
    assert canonicalize_merge_key("Malware", {"name": "HTTP://Evil.COM/X"})["name"] == "http://evil.com/x"


# --------------------------------------------------------------------------- read parity


# Every value above that is not defanged (the read side refangs a defanged one first, below).
PARITY = [v for v in [*LIVE_UPPER_CASE_HOSTS, *(v for v, _w in UNCHANGED), *(v for v, _k in FOLDED)] if refang(v) == v]


@pytest.mark.parametrize("value", PARITY)
def test_the_read_side_binds_the_write_key(value):
    assert normalize_indicator_value("url", value) == _key(value)


def test_the_parity_list_covers_the_cases():
    assert len(PARITY) >= 30 and "http://Setseta.COM:8080/X" in PARITY and "Setseta.COM/set.exe" in PARITY


@pytest.mark.parametrize(
    "pasted, expected",
    [
        ("HTTP://Setseta.COM/set.exe", ("url", "http://setseta.com/set.exe")),
        ("hxxp://Setseta[.]com/set.exe", ("url", "http://setseta.com/set.exe")),
        ("  http://D3f4.com.hk/OfJ3qDlVoGBRGjYK/conf.php ", ("url", "http://d3f4.com.hk/OfJ3qDlVoGBRGjYK/conf.php")),
    ],
)
def test_a_pasted_url_without_a_type_resolves_to_the_stored_key(pasted, expected):
    assert canonicalize_lookup(None, pasted) == expected
    assert canonicalize_lookup("url", pasted) == expected


# A url value MISP stored in the OTX event of the 730-day run of 2026-11-01 (pulse 67ca2991532d81738cbca1e8)
# whose scheme ``infer_indicator_type`` does not type url (it types only http, https and ftp).
LIVE_OTHER_SCHEME = (
    "htps://cdn.discordapp.com/attachments/1316109420995809283/1316112071376769165/NativeApp_G4QLIQRa.exe"
)

# Values the write side folds when they are typed url, while a lookup without a type does not infer url.
NOT_INFERRED_AS_URL = [
    LIVE_OTHER_SCHEME.replace("cdn.discordapp.com", "CDN.DiscordApp.COM"),
    "fxp://Evil.COM/x",
    "TCP://Evil.COM:4444/A",
    "wss://Evil.COM/Socket",
    "ssh://User@Evil.COM/X",  # inferred as an e-mail address
    "http://Evil.COM/A\nB",  # whitespace: not inferred at all
]
NO_TYPE = [None, "", "unknown"]  # no type: None, empty, the "unknown" sentinel (_blank_type_to_none)


@pytest.mark.parametrize("value", [*PARITY, *(v for v in NOT_INFERRED_AS_URL if v not in PARITY)])
@pytest.mark.parametrize("no_type", NO_TYPE)
def test_a_lookup_without_a_type_binds_the_url_write_key(value, no_type):
    """A value written as a url is found by a lookup that gives no type, whatever its scheme."""
    assert normalize_indicator_value(no_type, value) == _key(value)


@pytest.mark.parametrize("value", NOT_INFERRED_AS_URL)
def test_a_lookup_without_a_type_folds_the_value_and_keeps_the_inferred_type(value):
    assert infer_indicator_type(value) != "url"
    assert canonicalize_lookup(None, value) == (infer_indicator_type(value), _key(value))
    assert _key(value) != value, "each value has upper case in its scheme or host"


def test_the_live_value_of_another_scheme_resolves_to_its_stored_spelling():
    pasted = "HTPS://CDN.DiscordApp.COM/attachments/1316109420995809283/1316112071376769165/NativeApp_G4QLIQRa.exe"
    assert canonicalize_lookup(None, pasted) == (None, LIVE_OTHER_SCHEME)
    assert _key(pasted) == LIVE_OTHER_SCHEME


@pytest.mark.parametrize(
    "value",
    [
        "Invoice.EXE",
        "C:\\Users\\Public\\Run.EXE",
        "Global\\MutexName",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "mailto:Admin@Example.ORG",
        "jndi:ldap://Evil.COM/a",
        "http:// Evil.COM/",
        "Evil.COM/Path",
    ],
)
@pytest.mark.parametrize("no_type", NO_TYPE)
def test_a_value_without_a_type_that_does_not_read_as_scheme_and_host_keeps_its_case(value, no_type):
    assert normalize_indicator_value(no_type, value) == value


@pytest.mark.parametrize("indicator_type", ["filename", "text", "email", "registry"])
def test_a_lookup_of_another_case_sensitive_type_keeps_the_case_of_a_scheme_value(indicator_type):
    assert normalize_indicator_value(indicator_type, "fxp://Evil.COM/x") == "fxp://Evil.COM/x"


def test_a_lookup_without_a_type_never_raises_and_is_idempotent():
    alphabet = "hHtTpPsSfFxX:/.?#@[]()%{}\\ \t-_~!$&'*+,;=0123456789aAzZéÉ|"
    rng = random.Random(20261103)
    for _ in range(5000):
        value = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 30)))
        if rng.random() < 0.7:
            value = rng.choice(["http://", "fxp://", "TCP://", "htps://", "hxxp://", "Ssh://"]) + value
        out = normalize_indicator_value(None, value)
        assert isinstance(out, str)
        assert normalize_indicator_value(None, out) == out, value


# --------------------------------------------------------------------------- every Indicator caller


@pytest.fixture
def client():
    from neo4j_client import Neo4jClient

    c = Neo4jClient.__new__(Neo4jClient)
    c.driver = MagicMock()
    c.calls = []

    def run(query, *args, **kwargs):
        c.calls.append((query, kwargs))
        return MagicMock()

    session = MagicMock()
    session.run = run
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: False
    c.driver.session.return_value = session
    return c


UPPER, LOWER = "http://Setseta.com/set.exe", "http://setseta.com/set.exe"


def test_merge_indicator_keys_the_node_by_the_folded_url(client, monkeypatch):
    seen = {}

    def merge_node_with_source(label, key_props, data, source_id, **_kw):
        seen.update(label=label, key=key_props)
        return True

    monkeypatch.setattr(client, "merge_node_with_source", merge_node_with_source)
    assert client.merge_indicator({"indicator_type": "url", "value": UPPER}, source_id="alienvault_otx")
    assert seen == {"label": "Indicator", "key": {"indicator_type": "url", "value": LOWER}}


def test_merge_indicators_batch_writes_the_folded_url_and_its_uuid(client, monkeypatch):
    import neo4j_client

    rows = []

    def execute(_driver, _query, *, query_kwargs, batch_len, **_kw):
        rows.extend(query_kwargs["batch"])
        return True, batch_len

    monkeypatch.setattr(neo4j_client, "_execute_batch_with_retry", execute)
    assert client.merge_indicators_batch([{"indicator_type": "url", "value": UPPER}], source_id="alienvault_otx") == (
        1,
        0,
    )
    assert [(r["value"], r["node_uuid"]) for r in rows] == [
        (LOWER, compute_node_uuid("Indicator", {"indicator_type": "url", "value": LOWER}))
    ]


@pytest.mark.parametrize(
    "method, args, param",
    [
        ("create_indicator_vulnerability_relationship", ("CVE-2024-3400",), "value"),
        ("create_indicator_malware_relationship", ("KPOT Stealer",), "indicator_value"),
        ("create_indicator_sector_relationship", ("finance",), "indicator_value"),
    ],
)
def test_the_single_link_writers_match_the_folded_url(client, method, args, param):
    assert getattr(client, method)(UPPER, *args, source_id="alienvault_otx", indicator_type="url")
    bound = [kw[param] for q, kw in client.calls if "MATCH (i:Indicator" in q]
    assert bound and set(bound) == {LOWER}


def test_the_batch_link_writer_matches_the_folded_url(client):
    client.create_misp_relationships_batch(
        [
            {
                "rel_type": "INDICATES",
                "from_type": "Indicator",
                "from_key": {"indicator_type": "url", "value": UPPER},
                "to_type": "Malware",
                "to_key": {"name": "KPOT Stealer"},
                "confidence": 0.6,
                "misp_event_id": "55",
            }
        ],
        source_id="alienvault_otx",
    )
    rows = [r for _q, kw in client.calls for r in (kw.get("rows") or []) if "value" in r]
    assert rows and {r["value"] for r in rows} == {LOWER}


def test_the_alert_path_merges_the_folded_url(client):
    tx = MagicMock()
    tx.__enter__ = lambda s: s
    tx.__exit__ = lambda *a: False
    session = client.driver.session.return_value
    session.begin_transaction = MagicMock(return_value=tx)
    assert client.create_indicator_from_alert(UPPER, "url", "global")
    assert {c.kwargs["value"] for c in tx.run.call_args_list} == {LOWER}
