"""A MISP 2.5 REST double for the update paths of the vulnerability sources (2026-10).

Shared by ``tests/test_nvd_incremental_cursor.py`` (NVD) and ``tests/test_kev_update_path.py`` (CISA KEV).
``FakeMisp`` answers MISPWriter as MISP 2.5 does over an in-memory attribute store: the attribute listing
by tag (rows carry their event's ``id`` and ``info`` and the attribute ``timestamp``, as
``attributes/restSearch`` returns them), the lookup by value, event lookup and creation, the event edit
that adds attributes, and the attribute edit (``AttributesController::edit``: new comment and dates;
tags attached, or detached when marked ``deleted``; a new timestamp).
"""

from __future__ import annotations

import copy
import json
import uuid
from typing import Callable, Iterable, Optional


class Response:
    def __init__(self, status_code: int, body):
        self.status_code = status_code
        self._body = body
        self.headers: dict = {}
        self.text = json.dumps(body)[:300]
        self.content = self.text.encode()

    def json(self):
        return copy.deepcopy(self._body)


class FakeMisp:
    """MISP 2.5 REST answers over an in-memory attribute store (see the module docstring).

    ``event_info`` names the event of every attribute given; ``events`` can be changed afterwards (an
    analyst's event, for instance). ``clock`` returns the epoch seconds MISP stamps a write with; an edit
    always moves the attribute's timestamp past the stored one, as a save one second later does.
    """

    def __init__(
        self,
        attributes: Iterable[dict] = (),
        *,
        event_info: str = "EdgeGuard-nvd-2026-10-13",
        clock: Optional[Callable[[], float]] = None,
        url: str = "misp.test",
    ):
        self.attributes = [copy.deepcopy(a) for a in attributes]
        self.events = {a["event_id"]: event_info for a in self.attributes}
        self.clock = clock
        self.url = url
        self.posts: list = []
        self.headers: dict = {}
        self.edit_status: dict = {}  # uuid -> HTTP status MISP answers to its edit
        self.edits_not_stored: set = set()  # uuids MISP answers 200 for without storing the edit
        self.edits_keep_timestamp: set = set()  # uuids whose edit MISP stores without a new timestamp
        self.adds_not_stored: set = set()  # values MISP answers 200 for without storing them
        self.adds_without_list = False  # answer additions without the event's attribute list
        self.listing_status = None  # HTTP status of every attribute listing request
        self.rows_without_event = False  # listing rows without their ``Event`` (as a reduced answer)
        self.event_lookup_status = None  # HTTP status of every event lookup (``/events/restSearch``)

    def _now(self, at_least: float = 0.0) -> str:
        now = self.clock() if self.clock is not None else at_least
        return str(int(max(now, at_least)))

    def post(self, url, json=None, **_kwargs):
        path = url.split(self.url, 1)[1]
        self.posts.append((path, copy.deepcopy(json)))
        if path == "/attributes/restSearch":
            return self._rest_search(json or {})
        if path == "/events/restSearch":
            # MISP's exact Event.info filter (``eventinfo``, honoured from 2.4.177 on). The metadata rows carry
            # ``attribute_count`` as a string, as MISP 2.5.45 answers it.
            info = (json or {}).get("eventinfo")
            if self.event_lookup_status is not None:
                return Response(self.event_lookup_status, {"errors": "lookup failed"})
            return Response(
                200,
                {
                    "response": [
                        {"Event": {"id": i, "info": n, "attribute_count": str(self._count(i))}}
                        for i, n in self.events.items()
                        if n == info
                    ]
                },
            )
        if path == "/events":
            event_id = str(200 + len(self.events))
            self.events[event_id] = json["Event"]["info"]
            return Response(200, {"Event": {"id": event_id, "info": json["Event"]["info"]}})
        if path.startswith("/attributes/edit/"):
            return self._edit(path.rsplit("/", 1)[1], (json or {}).get("Attribute") or {})
        if path.startswith("/events/"):
            return self._add(path.rsplit("/", 1)[1], (json or {}).get("Attribute") or [])
        return Response(404, {})

    def get(self, url, **_kwargs):
        return Response(404, {})

    # ------------------------------------------------------------------ what the run did
    def edits(self) -> list:
        return [(p.rsplit("/", 1)[1], body["Attribute"]) for p, body in self.posts if p.startswith("/attributes/edit/")]

    def added_values(self) -> list:
        return [
            a["value"]
            for p, body in self.posts
            if p.startswith("/events/") and p != "/events/restSearch"
            for a in (body or {}).get("Attribute", [])
        ]

    def events_by_name(self, name: str) -> str:
        return next(i for i, n in self.events.items() if n == name)

    def by_value(self, value: str) -> dict:
        return next(a for a in self.attributes if a["value"] == value)

    def listings(self) -> list:
        return [body for p, body in self.posts if p == "/attributes/restSearch" and "tags" in (body or {})]

    def writes(self) -> list:
        """Every request that writes: additions, event creations and attribute edits."""
        return [
            p
            for p, _body in self.posts
            if p.startswith("/attributes/edit/") or (p.startswith("/events") and p != "/events/restSearch")
        ]

    # ------------------------------------------------------------------ answers
    def _count(self, event_id: str) -> int:
        return sum(1 for a in self.attributes if a["event_id"] == event_id)

    def _row(self, attr: dict) -> dict:
        row = copy.deepcopy(attr)
        if not self.rows_without_event:
            row["Event"] = {"id": attr["event_id"], "info": self.events.get(attr["event_id"], "")}
        return row

    def _rest_search(self, body: dict):
        if self.listing_status is not None:
            return Response(self.listing_status, {"errors": "listing failed"})
        if "eventid" in body:
            rows = [a for a in self.attributes if a["event_id"] == str(body["eventid"])]
        else:
            rows = [
                a
                for a in self.attributes
                if set(body.get("tags") or []) <= {t["name"] for t in a.get("Tag", [])}
                and a["type"] == body.get("type", a["type"])
            ]
        if "value" in body:
            wanted = set(body["value"]) if isinstance(body["value"], list) else {body["value"]}
            rows = [a for a in rows if a["value"] in wanted]
        page, limit = int(body.get("page", 1)), int(body.get("limit", 5000))
        return Response(
            200, {"response": {"Attribute": [self._row(a) for a in rows[(page - 1) * limit : page * limit]]}}
        )

    def _add(self, event_id: str, attributes: list):
        for attr in attributes:
            if attr["value"] in self.adds_not_stored:
                continue
            stored = copy.deepcopy(attr)
            stored.update(
                id=str(3000000 + len(self.attributes)), uuid=str(uuid.uuid4()), event_id=event_id, timestamp=self._now()
            )
            stored["Tag"] = [{"id": "0", "name": t["name"]} for t in attr.get("Tag", [])]
            self.attributes.append(stored)
        if self.adds_without_list:
            return Response(200, {"Event": {"id": event_id}})
        return Response(
            200, {"Event": {"id": event_id, "Attribute": [a for a in self.attributes if a["event_id"] == event_id]}}
        )

    def _edit(self, attr_uuid: str, changes: dict):
        if attr_uuid in self.edit_status:
            return Response(self.edit_status[attr_uuid], {"name": "Could not edit Attribute", "errors": {}})
        attr = next((a for a in self.attributes if a["uuid"] == attr_uuid), None)
        if attr is None:
            return Response(404, {"name": "Invalid attribute"})
        if attr_uuid not in self.edits_not_stored:
            for key in ("comment", "first_seen", "last_seen"):
                if key in changes:
                    attr[key] = changes[key]
            for tag in changes.get("Tag", []):
                names = [t["name"] for t in attr["Tag"]]
                if tag.get("deleted"):
                    attr["Tag"] = [t for t in attr["Tag"] if t["name"] != tag["name"]]
                elif tag["name"] not in names:
                    attr["Tag"].append({"id": "0", "name": tag["name"]})
            if attr_uuid not in self.edits_keep_timestamp:
                attr["timestamp"] = self._now(at_least=float(attr.get("timestamp") or 0) + 1)
        return Response(200, {"Attribute": copy.deepcopy(attr)})
