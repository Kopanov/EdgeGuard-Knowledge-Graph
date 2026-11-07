"""A MISP 2.5 double for Event Reports, answering with the shapes recorded on 2026-11-07 (report records).

Shared by ``tests/test_misp_push_reports.py`` and ``tests/test_report_pending.py``. ``ReportMisp`` holds events,
reports and tags in memory and answers ``MISPWriter``'s report requests with the answers of
``tests/fixtures/misp_event_reports_2026_11_07/answers.json`` (live checks L1-L12 on MISP 2.5.50): their status,
keys, value types and error bodies are the recorded ones; the uuid, name, content, distribution and deleted state
of the report, and the id, info and creator organisation of its event, are the double's own. The behaviour follows
the live checks: a uuid is unique across the instance, soft-deleted reports included (L3, L7: HTTP 403); a view or
an edit by an upper-case or unknown uuid answers 404 (L2); an edit takes only name, content and distribution (L2) and
a failed edit answers HTTP 200 ``[]`` (L2b); a name over 255 characters answers HTTP 500 (L8); ``addTag`` of an
unknown tag answers HTTP 200 ``{"saved": false}`` (L1b). ``GET /users/view/me`` answers the constructed shape of
``users_view_me_constructed.json`` (no recording exists).

Two answers come from the MISP source, not from a recording (``EventReportsController``, MISP 2.5.45 and 2.5.50):
``removeTag`` of a tag that is not on the report answers HTTP 200 ``{"saved": false, "errors": "Invalid
event-report - tag combination."}``, and ``addTag`` or ``removeTag`` of an unknown report answers HTTP 404
"Invalid report" (``fetchIfAuthorized``; the shape of the recorded ``edit_unknown_uuid``).

``script(method, path_prefix, key_or_answer, times)`` makes the next matching requests answer as recorded under
*key* (or a given ``(status, body)``), before the double's own logic: a recorded failure for one request. Given an
exception instead, the matching requests raise it (MISP did not answer: a timeout or a connection error).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from misp_fakes import Response

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "misp_event_reports_2026_11_07"
ANSWERS: Dict[str, Any] = json.loads((FIXTURES / "answers.json").read_text(encoding="utf-8"))
ME_ANSWER: Dict[str, Any] = json.loads((FIXTURES / "users_view_me_constructed.json").read_text(encoding="utf-8"))[
    "answer"
]
URL = "https://misp.test"
ORG_NAMES = {"1": "ADMIN"}


def recorded(key: str) -> Tuple[int, Any]:
    """The recorded status and answer of *key*."""
    entry = ANSWERS[key]
    return entry["status"], copy.deepcopy(entry["answer"])


class ReportMisp:
    """In-memory MISP for report records (see the module docstring)."""

    def __init__(self, *, org_id: str = "1"):
        self.url = URL
        self.headers: dict = {}
        self.events: Dict[str, Dict[str, Any]] = {}
        self.reports: Dict[str, Dict[str, Any]] = {}
        # tlp:white has id 78 on the recording MISP (tags_search_tlp); the others are given ids here.
        self.tags: Dict[str, str] = {"EdgeGuard": "1", "tlp:white": "78"}
        self.requests: List[Tuple[str, str, Any]] = []
        self._script: List[List[Any]] = []
        self.me = copy.deepcopy(ME_ANSWER)
        self.me["User"]["org_id"] = org_id
        self.me["Organisation"]["id"] = org_id
        self._next_report = 1

    # ------------------------------------------------------------------ set-up
    def add_event(self, event_id: str, info: str, *, orgc_id: str = "1", attribute_count: int = 0) -> None:
        self.events[str(event_id)] = {"info": info, "orgc_id": orgc_id, "attribute_count": attribute_count}

    def add_tag(self, name: str, tag_id: str) -> None:
        self.tags[name] = tag_id

    def store(
        self,
        uuid: str,
        event_id: str,
        *,
        name: str,
        content: str,
        distribution: int = 5,
        deleted: bool = False,
        tags: Tuple[str, ...] = (),
    ) -> Dict[str, Any]:
        report = {
            "id": str(self._next_report),
            "uuid": uuid,
            "event_id": str(event_id),
            "name": name,
            "content": content,
            "distribution": str(distribution),
            "deleted": deleted,
            "tags": set(tags),
        }
        self._next_report += 1
        self.reports[uuid] = report
        return report

    def script(
        self, method: str, path_prefix: str, answer: Union[str, Tuple[int, Any], BaseException], times: int = 1
    ) -> None:
        if isinstance(answer, BaseException):
            status, body = None, answer
        else:
            status, body = recorded(answer) if isinstance(answer, str) else answer
        self._script.append([method, path_prefix, status, body, times])

    # ------------------------------------------------------------------ what the writer asked
    def paths(self, method: Optional[str] = None) -> List[str]:
        return [p for m, p, _b in self.requests if method is None or m == method]

    def bodies(self, path_prefix: str) -> List[Any]:
        return [b for _m, p, b in self.requests if p.startswith(path_prefix)]

    def writes(self) -> List[str]:
        """Every request that changes MISP (the tag search is a POST that reads)."""
        return [p for m, p, _b in self.requests if m == "POST" and p not in ("/events/restSearch", "/tags/search/x/1")]

    # ------------------------------------------------------------------ requests.Session
    def post(self, url, json=None, **_kwargs):
        return self._handle("POST", url, json)

    def get(self, url, **_kwargs):
        return self._handle("GET", url, None)

    def _handle(self, method: str, url: str, body: Any):
        path = url.split(self.url, 1)[1]
        self.requests.append((method, path, copy.deepcopy(body)))
        for entry in self._script:
            if entry[0] == method and path.startswith(entry[1]) and entry[4] > 0:
                entry[4] -= 1
                if isinstance(entry[3], BaseException):
                    raise entry[3]
                return Response(entry[2], copy.deepcopy(entry[3]))
        if method == "GET" and path == "/users/view/me":
            return Response(200, copy.deepcopy(self.me))
        if method == "POST" and path == "/events/restSearch":
            return self._event_lookup((body or {}).get("eventinfo"))
        if method == "POST" and path == "/events":
            return self._event_create(body["Event"]["info"])
        if method == "POST" and path.startswith("/eventReports/add/"):
            return self._add(path.rsplit("/", 1)[1], body["EventReport"])
        if method == "GET" and path.startswith("/eventReports/view/"):
            return self._view(path.rsplit("/", 1)[1])
        if method == "POST" and path.startswith("/eventReports/edit/"):
            return self._edit(path.rsplit("/", 1)[1], body["EventReport"])
        if method == "POST" and path.startswith(("/eventReports/addTag/", "/eventReports/removeTag/")):
            _blank, _er, action, report_id, tag_id = path.split("/")
            return self._tag(action, report_id, tag_id)
        if method == "POST" and path == "/tags/search/x/1":
            return self._tag_search(body.get("tag") or [])
        return Response(404, {"name": "Not Found", "message": "Not Found", "url": path})

    # ------------------------------------------------------------------ answers
    def _event_lookup(self, info: str):
        _status, template = recorded("events_restsearch_metadata_row")
        rows = []
        for event_id, event in self.events.items():
            if event["info"] != info:
                continue
            row = copy.deepcopy(template["response"][0])
            row["Event"].update(
                id=event_id, info=event["info"], orgc_id=event["orgc_id"], attribute_count=str(event["attribute_count"])
            )
            rows.append(row)
        return Response(200, {"response": rows})

    def _event_create(self, info: str):
        event_id = str(200 + len(self.events))
        self.add_event(event_id, info)
        _status, answer = recorded("events_add")
        answer["Event"].update(id=event_id, info=info, attribute_count="0")
        return Response(200, answer)

    def _event_part(self, report: Dict[str, Any]) -> Dict[str, Any]:
        event = self.events.get(report["event_id"], {"info": "", "orgc_id": "1"})
        org = event["orgc_id"]
        name = ORG_NAMES.get(org, f"org {org}")
        return {
            "id": report["event_id"],
            "orgc_id": org,
            "org_id": org,
            "info": event["info"],
            "user_id": "1",
            "date": "2026-11-07",
            "Org": {"id": org, "name": name},
            "Orgc": {"id": org, "name": name},
        }

    def _report_answer(self, key: str, report: Dict[str, Any]):
        status, answer = recorded(key)
        answer["EventReport"].update({k: report[k] for k in ("id", "uuid", "event_id", "name", "content")})
        answer["EventReport"]["distribution"] = report["distribution"]
        answer["EventReport"]["deleted"] = report["deleted"]
        answer["Event"] = self._event_part(report)
        return Response(status, answer)

    def _not_found(self, key: str, path: str):
        status, answer = recorded(key)
        answer["url"] = path
        return Response(status, answer)

    def _add(self, event_id: str, sent: Dict[str, Any]):
        uuid = sent.get("uuid")
        if uuid in self.reports or (isinstance(uuid, str) and uuid.lower() in self.reports):
            return Response(*recorded("add_duplicate_uuid"))
        if not sent.get("name"):
            status, answer = recorded("add_duplicate_uuid")
            answer["errors"] = "This field cannot be left blank"  # L2b: an add without a name
            return Response(status, answer)
        if len(sent["name"]) > 255:
            return Response(*recorded("add_name_300_chars"))
        report = self.store(
            uuid,
            event_id,
            name=sent["name"],
            content=sent["content"],
            distribution=int(sent["distribution"]),
            tags=tuple(t["name"] for t in sent.get("Tag") or [] if t["name"] in self.tags),
        )
        return self._report_answer("add_ok", report)

    def _view(self, uuid: str):
        report = self.reports.get(uuid)
        if report is None:
            return self._not_found("view_upper_case_uuid", f"/eventReports/view/{uuid}")
        return self._report_answer("view_ok", report)

    def _edit(self, uuid: str, sent: Dict[str, Any]):
        report = self.reports.get(uuid)
        if report is None:
            return self._not_found("edit_unknown_uuid", f"/eventReports/edit/{uuid}")
        if "name" in sent and not sent["name"]:
            return Response(*recorded("edit_blank_name"))
        if "distribution" in sent and int(sent["distribution"]) not in (0, 1, 2, 3, 4, 5):
            return Response(*recorded("edit_invalid_distribution"))
        if len(sent.get("name") or "") > 255:
            return Response(*recorded("edit_name_256_chars"))
        for key in ("name", "content"):
            if key in sent:
                report[key] = sent[key]
        if "distribution" in sent:
            report["distribution"] = str(sent["distribution"])
        return self._report_answer("edit_ok", report)

    def _tag(self, action: str, report_id: str, tag_id: str):
        report = next((r for r in self.reports.values() if r["id"] == report_id or r["uuid"] == report_id), None)
        if report is None:  # fetchIfAuthorized: 404 "Invalid report" (MISP source)
            return self._not_found("edit_unknown_uuid", f"/eventReports/{action}/{report_id}/{tag_id}")
        names = {v: k for k, v in self.tags.items()}
        if tag_id not in names:
            return Response(*recorded("add_tag_unknown_name"))
        name = names[tag_id]
        if action == "addTag":
            if name in report["tags"]:
                return Response(*recorded("add_tag_already_attached"))
            report["tags"].add(name)
            return Response(*recorded("add_tag_by_id"))
        if name not in report["tags"]:  # EventReportsController::removeTag (MISP source, not recorded)
            return Response(200, {"saved": False, "errors": "Invalid event-report - tag combination."})
        report["tags"].discard(name)
        return Response(*recorded("remove_tag_by_id"))

    def _tag_search(self, names: List[str]):
        _status, template = recorded("tags_search_tlp")
        rows = []
        for name in names:
            if name not in self.tags:
                continue
            row = copy.deepcopy(template[0])
            row["Tag"].update(id=self.tags[name], name=name)
            if not name.startswith("tlp:"):
                row.pop("Taxonomy", None)
                row.pop("TaxonomyPredicate", None)
            rows.append(row)
        return Response(200, rows)
