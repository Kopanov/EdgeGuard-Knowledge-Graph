"""4-byte UTF-8 characters must not reach MISP's 3-byte ``utf8`` columns.

Found on the 2026-10-12 fresh baseline: an OTX pulse name with a flag emoji in the attribute
comment made MISP's INSERT fail (``1366 Incorrect string value``) and MISP rejected the whole
batch with HTTP 500 after every retry, losing 500 unrelated indicators.
"""

from unittest.mock import MagicMock

from collectors import misp_writer as mw

FLAG = "\U0001f1ee\U0001f1f7"  # regional indicators, 4 bytes each in UTF-8


def test_comment_and_tag_names_are_stripped_and_the_indicator_kept():
    attrs = [
        {
            "type": "domain",
            "value": "example.org",
            "comment": f"OTX pulse: Campaign {FLAG} Iran",
            "Tag": [{"name": f"source:{FLAG}otx"}, {"name": "tlp:clear"}],
        }
    ]
    out = mw._make_attributes_storable(attrs)
    assert out == [
        {
            "type": "domain",
            "value": "example.org",
            "comment": "OTX pulse: Campaign  Iran",
            "Tag": [{"name": "source:otx"}, {"name": "tlp:clear"}],
        }
    ]
    assert attrs[0]["comment"].endswith("Iran") and FLAG in attrs[0]["comment"]  # input not mutated


def test_value_with_four_byte_characters_is_skipped_not_rewritten():
    attrs = [
        {"type": "url", "value": f"https://x.example/{FLAG}"},
        {"type": "domain", "value": "ok.example", "comment": "plain é ü 中"},
    ]
    out = mw._make_attributes_storable(attrs)
    assert out == [{"type": "domain", "value": "ok.example", "comment": "plain é ü 中"}]


def test_push_batch_sends_the_cleaned_batch_and_counts_skips_as_failed():
    w = mw.MISPWriter.__new__(mw.MISPWriter)
    w.url = "https://misp.local"
    w.verify_ssl = False
    w.stats = {"attributes_added": 0, "batches_sent": 0, "errors": 0}
    good = {"type": "domain", "value": "ok.example", "comment": f"a{FLAG}b"}
    bad = {"type": "url", "value": f"https://x.example/{FLAG}"}
    response = MagicMock(status_code=200)
    response.json.return_value = {"Event": {"Attribute": [{"type": "domain", "value": "ok.example"}]}}
    w.session = MagicMock()
    w.session.post.return_value = response

    ok, failed = w._push_batch("349", [good, bad])

    sent = w.session.post.call_args.kwargs["json"]["Attribute"]
    assert sent == [{"type": "domain", "value": "ok.example", "comment": "ab"}]
    assert (ok, failed) == (1, 1)
