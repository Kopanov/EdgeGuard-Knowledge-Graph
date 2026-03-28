"""Incremental checkpoints + MISP prefetch (duplicate avoidance)."""

from unittest.mock import MagicMock, patch


def test_update_source_incremental_merges_under_incremental_key():
    from baseline_checkpoint import clear_checkpoint, get_source_incremental, update_source_incremental

    clear_checkpoint("testsrc_incr")
    update_source_incremental("testsrc_incr", foo="bar")
    assert get_source_incremental("testsrc_incr") == {"foo": "bar"}
    update_source_incremental("testsrc_incr", baz=1)
    assert get_source_incremental("testsrc_incr") == {"foo": "bar", "baz": 1}
    clear_checkpoint("testsrc_incr")


def test_misp_writer_push_items_skips_prefetched_type_value():
    from collectors import misp_writer as mw

    w = mw.MISPWriter.__new__(mw.MISPWriter)
    w.url = "https://misp.test"
    w.verify_ssl = True
    w.stats = {
        "events_created": 0,
        "attributes_added": 0,
        "batches_sent": 0,
        "errors": 0,
        "attrs_skipped_existing": 0,
    }
    w.session = MagicMock()

    def post_side_effect(url, **kwargs):
        r = MagicMock()
        if "events/restSearch" in url:
            r.status_code = 200
            r.json.return_value = {"response": [{"Event": {"id": "99", "info": "EdgeGuard-GLOBAL-otx-2099-01-01"}}]}
        elif "attributes/restSearch" in url:
            r.status_code = 200
            r.json.return_value = {
                "response": [
                    {"type": "ip-dst", "value": "1.1.1.1"},
                ]
            }
        elif "/events" in url and url.endswith("/events"):
            r.status_code = 201
            r.json.return_value = {"Event": {"id": "99", "info": "EdgeGuard-GLOBAL-otx-2099-01-01"}}
        else:
            r.status_code = 200
            r.json.return_value = {}
        return r

    w.session.post.side_effect = post_side_effect

    with patch.object(mw.MISPWriter, "_get_or_create_event", return_value="99"):
        with patch.object(mw.MISPWriter, "_push_batch", return_value=(1, 0)) as pb:
            with patch("collectors.misp_writer.MISP_PREFETCH_EXISTING_ATTRS", True):
                items = [
                    {
                        "indicator_type": "ipv4",
                        "value": "1.1.1.1",
                        "zone": ["global"],
                        "tag": "otx",
                    },
                    {
                        "indicator_type": "ipv4",
                        "value": "8.8.8.8",
                        "zone": ["global"],
                        "tag": "otx",
                    },
                ]
                ok, bad = mw.MISPWriter.push_items(w, items, batch_size=50)
    assert ok == 1 and bad == 0
    pb.assert_called_once()
    batch = pb.call_args[0][1]
    assert len(batch) == 1
    assert batch[0]["value"] == "8.8.8.8"
    assert w.stats["attrs_skipped_existing"] == 1


def test_otx_max_pulse_modified_iso():
    from collectors.otx_collector import OTXCollector

    pulses = [
        {"modified": "2020-01-01T00:00:00Z"},
        {"modified": "2021-06-15T12:00:00+00:00"},
    ]
    assert OTXCollector._max_pulse_modified_iso(pulses).startswith("2021-06-15")


def test_mitre_conditional_get_skips_body_on_304():
    from collectors import mitre_collector as mc

    class Resp:
        def __init__(self, code, etag_out=None):
            self.status_code = code
            self.headers = {"ETag": etag_out} if etag_out else {}

        def json(self):
            return {"objects": []}

    def fake_req_304(method, url, **kwargs):
        return Resp(304)

    with patch.object(mc, "request_with_rate_limit_retries", side_effect=fake_req_304):
        c = mc.MITRECollector.__new__(mc.MITRECollector)
        c.attack_url = "https://example.com/bundle.json"
        bundle, etag = mc.MITRECollector._download_stix_bundle(c, etag='"v1"')
        assert bundle is None
        assert etag == '"v1"'


def test_mitre_download_returns_bundle_on_200():
    from collectors import mitre_collector as mc

    class Resp:
        status_code = 200
        headers = {"ETag": '"abc"'}

        def json(self):
            return {"objects": []}

    with patch.object(mc, "request_with_rate_limit_retries", return_value=Resp()):
        c = mc.MITRECollector.__new__(mc.MITRECollector)
        c.attack_url = "https://example.com/bundle.json"
        bundle, new_etag = mc.MITRECollector._download_stix_bundle(c, etag=None)
        assert bundle == {"objects": []}
        assert new_etag == '"abc"'
