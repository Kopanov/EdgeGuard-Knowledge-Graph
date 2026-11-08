"""The sync reads a whole MISP event without its galaxy clusters (2026-11-08).

MISP attaches to every galaxy tag (``misp-galaxy:mitre-attack-pattern="... - T1677"``) the whole cluster under
``Galaxy``; on the ATT&CK event of the 730-day test instance the clusters were 88% of a 118 MB answer. The sync reads
only tag names, so ``fetch_event_details`` asks for ``/events/view/<id>/excludeGalaxy:1``, which answered 13.7 MB with
the same attributes and tags. When MISP answers that request with a 4xx, or with a body that is not an event, a
``[MISP-VIEW-FALLBACK]`` warning is logged and the event is read once as before (PyMISP ``get_event``, then REST
``/events/<id>``). A 5xx of that request is retried like a transport error, so a struggling MISP gets no read with
the clusters; after the retries the event goes to the paged fetch.

Answers: ``tests/fixtures/misp_event_view_galaxies_2026_11_08.json``, MISP 2.5.50's answers to both views of event 135
(EdgeGuard-mitre_attck-2026-11-08), reduced to the attributes T1677 and T1027.017. The PyMISP double and the HTTP
statuses of the refusals are constructed; MISP 2.5.50 answered both views with 200.
"""

from __future__ import annotations

import copy
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from misp_fakes import Response  # noqa: E402
from stub_cleanup import clear_graphql_api_magicmock_stubs  # noqa: E402

# tests/test_graphql_api.py replaces neo4j_client (and neo4j, pymisp) with MagicMocks when it is collected first.
if any(isinstance(m, MagicMock) for k, m in list(sys.modules.items()) if k == "neo4j_client" or k.startswith("neo4j")):
    clear_graphql_api_magicmock_stubs()

import run_misp_to_neo4j  # noqa: E402
from run_misp_to_neo4j import (  # noqa: E402
    MAX_RETRIES,
    MISP_CONNECT_TIMEOUT,
    MISP_REQUEST_TIMEOUT,
    SSL_VERIFY,
    MISPToNeo4jSync,
    MispTransientServerError,
)

_FIXTURE = json.loads(
    (REPO_ROOT / "tests" / "fixtures" / "misp_event_view_galaxies_2026_11_08.json").read_text(encoding="utf-8")
)
WITH_GALAXIES = _FIXTURE["with_galaxies"]
WITHOUT_GALAXIES = _FIXTURE["without_galaxies"]
EVENT_ID = "135"
INFO = WITHOUT_GALAXIES["Event"]["info"]
VIEW = f"/events/view/{EVENT_ID}/excludeGalaxy:1"
REST = f"/events/{EVENT_ID}"
MISP = "https://misp.test"


def _tag_names(tags: Any) -> List[str]:
    return sorted(t["name"] for t in tags or [])


def _session(answers: Dict[str, Any]) -> MagicMock:
    """A requests session whose GET answers each URL path of ``answers``: a ``Response``, an exception to raise,
    or a list of them taken in turn."""
    session = MagicMock()

    def get(url: str, **_kwargs: Any) -> Any:
        answer = answers[url[len(MISP) :]]
        if isinstance(answer, list):
            answer = answer.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    session.get.side_effect = get
    return session


def _syncer(answers: Dict[str, Any]) -> MISPToNeo4jSync:
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    syncer.misp_url = MISP
    syncer.session = _session(answers)
    return syncer


def _paths(syncer: MISPToNeo4jSync) -> List[str]:
    return [c.args[0][len(MISP) :] for c in syncer.session.get.call_args_list]


class _PyMISP:
    """PyMISP's ``get_event`` answering MISP's view with the clusters (constructed double; ``calls`` counts)."""

    calls: List[str] = []
    answer: Any = None

    def __init__(self, *_a: Any, **_kw: Any):
        pass

    def get_event(self, event_id: str) -> Any:
        _PyMISP.calls.append(event_id)
        if isinstance(_PyMISP.answer, BaseException):
            raise _PyMISP.answer
        return copy.deepcopy(_PyMISP.answer)


@pytest.fixture
def pymisp_double(monkeypatch):
    import pymisp

    _PyMISP.calls = []
    _PyMISP.answer = WITH_GALAXIES
    monkeypatch.setattr(pymisp, "PyMISP", _PyMISP)
    return _PyMISP


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    monkeypatch.setattr(run_misp_to_neo4j.time, "sleep", lambda *_a, **_k: None)


# --------------------------------------------------------------------------- the recorded answers


def test_the_recorded_views_differ_only_in_their_galaxy_clusters():
    """The guard of this file: MISP keeps every attribute and tag, ``misp-galaxy:*`` tags included, and leaves
    out the clusters."""
    full, bare = WITH_GALAXIES["Event"], WITHOUT_GALAXIES["Event"]
    assert [a["uuid"] for a in full["Attribute"]] == [a["uuid"] for a in bare["Attribute"]]
    assert len(full["Attribute"]) == 2
    for with_c, without_c in zip(full["Attribute"], bare["Attribute"], strict=True):
        assert _tag_names(with_c["Tag"]) == _tag_names(without_c["Tag"])
        assert any(name.startswith("misp-galaxy:mitre-attack-pattern=") for name in _tag_names(without_c["Tag"]))
        assert with_c["Galaxy"] and with_c["Galaxy"][0]["GalaxyCluster"] and without_c["Galaxy"] == []
        assert {k: v for k, v in with_c.items() if k != "Galaxy"} == {
            k: v for k, v in without_c.items() if k != "Galaxy"
        }
    assert _tag_names(full["Tag"]) == _tag_names(bare["Tag"])
    assert {k: v for k, v in full.items() if k != "Attribute"} == {k: v for k, v in bare.items() if k != "Attribute"}
    assert len(json.dumps(WITHOUT_GALAXIES)) < len(json.dumps(WITH_GALAXIES)) / 2


# --------------------------------------------------------------------------- the view without clusters


def test_the_whole_event_fetch_asks_for_the_view_without_galaxy_clusters(pymisp_double):
    syncer = _syncer({VIEW: Response(200, WITHOUT_GALAXIES)})
    event = syncer.fetch_event_details(EVENT_ID)
    assert event == WITHOUT_GALAXIES["Event"]
    assert _paths(syncer) == [VIEW] and pymisp_double.calls == []
    (call,) = syncer.session.get.call_args_list
    assert call.kwargs == {"verify": SSL_VERIFY, "timeout": (MISP_CONNECT_TIMEOUT, MISP_REQUEST_TIMEOUT)}


def test_the_parameter_is_a_named_parameter_of_the_view_path():
    """CakePHP reads ``excludeGalaxy:1`` as a named parameter of ``/events/view/<id>``, the form MISP 2.5.50
    answered without clusters; PyMISP's ``get_event`` has no such argument."""
    syncer = _syncer({VIEW: Response(200, WITHOUT_GALAXIES)})
    syncer.fetch_event_details(EVENT_ID)
    (call,) = syncer.session.get.call_args_list
    assert call.args == (f"{MISP}/events/view/135/excludeGalaxy:1",) and "params" not in call.kwargs


def _processing_syncer(answers: Dict[str, Any]) -> MISPToNeo4jSync:
    syncer = _syncer(answers)
    syncer.written: List[Dict[str, Any]] = []
    syncer.sync_to_neo4j = lambda items: (syncer.written.extend(items), (len(items), 0, []))[1]
    syncer._write_cross_item_relationships = lambda rels: 0
    syncer._create_relationships = lambda rels, source: 0
    syncer._count_relationship_writes = lambda written: None
    return syncer


def test_the_sync_writes_the_same_items_from_both_views(pymisp_double):
    """Through ``_process_single_event`` (the sync's caller): the view without clusters, and the view with them
    read through the fallback, give the same items. No reader of the sync takes anything from ``Galaxy``."""
    bare = _processing_syncer({VIEW: Response(200, WITHOUT_GALAXIES)})
    assert bare._process_single_event(EVENT_ID, INFO, 2) == (2, 0, 0)
    assert pymisp_double.calls == []
    full = _processing_syncer({VIEW: Response(400, {"message": "error"})})
    assert full._process_single_event(EVENT_ID, INFO, 2) == (2, 0, 0)
    assert pymisp_double.calls == [EVENT_ID]
    assert bare.written == full.written
    assert sorted(item["mitre_id"] for item in bare.written) == ["T1027.017", "T1677"]
    assert bare.stats["events_processed"] == full.stats["events_processed"] == 1


def test_the_stix_fallback_reads_the_view_without_galaxy_clusters(pymisp_double):
    """The other caller: when MISP's STIX export fails, the event is read whole and converted."""
    syncer = _syncer(
        {f"/events/{EVENT_ID}/stix2": Response(404, {"message": "Not found"}), VIEW: Response(200, WITHOUT_GALAXIES)}
    )
    bundle = syncer.fetch_stix21_from_misp(EVENT_ID)
    assert _paths(syncer) == [f"/events/{EVENT_ID}/stix2", VIEW] and pymisp_double.calls == []
    assert bundle.get("type") == "bundle" and bundle.get("objects")


# --------------------------------------------------------------------------- MISP refuses the view


@pytest.mark.parametrize("status", [400, 403, 404, 405])
def test_a_refused_view_is_read_once_with_its_clusters(pymisp_double, caplog, status):
    syncer = _syncer({VIEW: Response(status, {"message": "refused"})})
    with caplog.at_level(logging.WARNING, logger="run_misp_to_neo4j"):
        event = syncer.fetch_event_details(EVENT_ID)
    assert event == WITH_GALAXIES["Event"]
    assert _paths(syncer) == [VIEW] and pymisp_double.calls == [EVENT_ID]
    warnings = [r.getMessage() for r in caplog.records if "[MISP-VIEW-FALLBACK]" in r.getMessage()]
    assert warnings == [
        f"[MISP-VIEW-FALLBACK] Event {EVENT_ID}: {VIEW} answered HTTP {status}; reading the event once with its "
        f"galaxy clusters (PyMISP get_event, then REST /events/{EVENT_ID})"
    ]
    assert all(r.levelno == logging.WARNING for r in caplog.records if "[MISP-VIEW-FALLBACK]" in r.getMessage())


class _NotJson(Response):
    def json(self):
        raise requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0)


@pytest.mark.parametrize(
    "answer",
    [_NotJson(200, None), Response(200, {"errors": "no event"}), Response(200, [])],
    ids=["html", "errors", "list"],
)
def test_a_2xx_body_that_is_no_event_is_read_once_with_its_clusters(pymisp_double, caplog, answer):
    syncer = _syncer({VIEW: answer})
    with caplog.at_level(logging.WARNING, logger="run_misp_to_neo4j"):
        assert syncer.fetch_event_details(EVENT_ID) == WITH_GALAXIES["Event"]
    assert pymisp_double.calls == [EVENT_ID]
    assert any("answered a body that is not an event" in r.getMessage() for r in caplog.records)


def test_the_rest_request_follows_when_pymisp_fails(pymisp_double):
    pymisp_double.answer = RuntimeError("PyMISP unavailable")
    syncer = _syncer({VIEW: Response(404, {"message": "Not found"}), REST: Response(200, WITH_GALAXIES)})
    assert syncer.fetch_event_details(EVENT_ID) == WITH_GALAXIES["Event"]
    assert _paths(syncer) == [VIEW, REST] and pymisp_double.calls == [EVENT_ID]


def test_an_event_missing_everywhere_is_none_after_one_round(pymisp_double):
    """A 4xx stays permanent: one round of requests, no retry, None (the caller counts the event as failed)."""
    pymisp_double.answer = {"errors": (404, "Invalid event")}
    syncer = _syncer({VIEW: Response(404, {"message": "Not found"}), REST: Response(404, {"message": "Not found"})})
    assert syncer.fetch_event_details(EVENT_ID) is None
    assert _paths(syncer) == [VIEW, REST] and pymisp_double.calls == [EVENT_ID]


# --------------------------------------------------------------------------- retries keep their handling


def test_a_transport_error_of_the_view_is_retried_without_the_fallback(pymisp_double):
    syncer = _syncer(
        {
            VIEW: [
                requests.exceptions.ConnectionError("reset"),
                requests.exceptions.ReadTimeout("slow"),
                Response(200, WITHOUT_GALAXIES),
            ]
        }
    )
    assert syncer.fetch_event_details(EVENT_ID) == WITHOUT_GALAXIES["Event"]
    assert _paths(syncer) == [VIEW, VIEW, VIEW] and pymisp_double.calls == []


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_a_5xx_of_the_view_is_retried_and_then_raised_without_the_clusters(pymisp_double, caplog, status):
    """A 5xx of the light request is retried like a transport error and never followed by the read with the
    clusters; after the retries it is raised, and ``_process_single_event`` turns to the paged fetch."""
    pymisp_double.answer = RuntimeError("Error code 500")
    syncer = _syncer({VIEW: Response(status, {}), REST: Response(503, {})})
    with caplog.at_level(logging.WARNING, logger="run_misp_to_neo4j"):
        with pytest.raises(MispTransientServerError):
            syncer.fetch_event_details(EVENT_ID)
    assert _paths(syncer) == [VIEW] * (MAX_RETRIES + 1)
    assert pymisp_double.calls == []
    assert not any("[MISP-VIEW-FALLBACK]" in r.getMessage() for r in caplog.records)


def test_the_view_answers_again_after_a_5xx(pymisp_double):
    pymisp_double.answer = RuntimeError("Error code 500")
    syncer = _syncer({VIEW: [Response(503, {}), Response(200, WITHOUT_GALAXIES)], REST: Response(503, {})})
    assert syncer.fetch_event_details(EVENT_ID) == WITHOUT_GALAXIES["Event"]
    assert _paths(syncer) == [VIEW, VIEW] and pymisp_double.calls == []


def test_a_5xx_of_the_rest_request_after_a_refused_view_is_retried(pymisp_double):
    """The old path keeps its handling: after a 4xx of the light request, a 5xx of the REST request is retried."""
    pymisp_double.answer = RuntimeError("Error code 500")
    syncer = _syncer({VIEW: Response(404, {}), REST: Response(503, {})})
    with pytest.raises(MispTransientServerError):
        syncer.fetch_event_details(EVENT_ID)
    assert _paths(syncer) == [VIEW, REST] * (MAX_RETRIES + 1)
    assert pymisp_double.calls == [EVENT_ID] * (MAX_RETRIES + 1)
