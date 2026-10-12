"""Generic ``hash`` indicators take their MISP type from the digest length.

Found on the 2026-10-12 fresh baseline: the OTX collector maps every ``FileHash-*`` indicator to
the generic ``hash`` type, and ``map_indicator_type`` turned all of them into ``sha256``. MISP
answers HTTP 200 and silently drops a ``sha256`` attribute whose value is 32 or 40 hex characters,
so every OTX MD5 and SHA1 was lost (31,029 absent attributes in 202 ``[UNCONFIRMED]`` batches).
"""

from collectors import misp_writer as mw


def _writer():
    return mw.MISPWriter.__new__(mw.MISPWriter)


def test_generic_hash_is_typed_by_digest_length():
    w = _writer()
    assert w.map_indicator_type("hash", "d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert w.map_indicator_type("hash", "da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert w.map_indicator_type("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
    assert (
        w.map_indicator_type(
            "hash",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        )
        == "sha512"
    )
    assert w.map_indicator_type("hash", " D41D8CD98F00B204E9800998ECF8427E ") == "md5"


def test_generic_hash_without_a_usable_value_keeps_the_default():
    w = _writer()
    assert w.map_indicator_type("hash") == "sha256"
    assert w.map_indicator_type("hash", "") == "sha256"
    assert w.map_indicator_type("hash", "not-a-digest") == "sha256"
    assert w.map_indicator_type("hash", "abcdef") == "sha256"


def test_explicit_hash_types_are_untouched():
    w = _writer()
    assert w.map_indicator_type("md5", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "md5"
    assert w.map_indicator_type("sha256", "d41d8cd98f00b204e9800998ecf8427e") == "sha256"
