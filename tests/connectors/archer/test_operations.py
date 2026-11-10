"""Archer read operation tests."""

import asyncio
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors.archer.models import (
    ApplicationRef,
    AttachmentRef,
    ContentRef,
    EmptyInput,
    LevelRef,
    SearchContentArgs,
    ValuesListRef,
)
from icuhub.kit import BudgetExhausted, VendorContractError

from .conftest import RouteTransport, make_archer

CLIENT = Path(__file__).parents[2] / "fixtures" / "archer" / "client"
OPS = Path(__file__).parents[2] / "fixtures" / "archer" / "operations"
LOGIN = ("POST", "/platformapi/core/security/login")


def fixture(base: Path, name: str):
    return json.loads((base / name).read_text(encoding="utf-8"))


def base_routes() -> dict[tuple[str, str], Any]:
    return {LOGIN: {"json": fixture(CLIENT, "login.json")}}


def test_get_version():
    routes = base_routes()
    routes[("POST", "/platformapi/core/system/applicationinfo")] = {"json": fixture(CLIENT, "app_info.json")}
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.get_version(EmptyInput()))
    assert out.version == "2025.10"
    assert out.raw["BuildNumber"] == "2025.10.0.123"


def test_list_applications_omits_permission_filtered_entries():
    routes = base_routes()
    routes[("POST", "/platformapi/core/system/application")] = {"json": fixture(CLIENT, "applications.json")}
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.list_applications(EmptyInput()))
    assert [i.id for i in out.items] == [301]
    assert out.items[0].name == "Risk Register"


def test_list_levels():
    routes = base_routes()
    routes[("POST", "/platformapi/core/system/level/module/301")] = {"json": fixture(OPS, "levels.json")}
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.list_levels(ApplicationRef(application_id=301)))
    assert [i.id for i in out.items] == [401]


def test_list_fields():
    routes = base_routes()
    routes[("POST", "/platformapi/core/system/fielddefinition/level/401")] = {
        "json": fixture(CLIENT, "fields_level.json")
    }
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.list_fields(LevelRef(level_id=401)))
    assert [i.id for i in out.items] == [5001, 5002, 5003]
    assert out.items[2].raw["RelatedValuesListId"] == 701


def test_list_values_flattens_tree_with_depth():
    routes = base_routes()
    routes[("POST", "/platformapi/core/system/valueslistvalue/valueslist/701")] = {
        "json": fixture(CLIENT, "values_list.json")
    }
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.list_values(ValuesListRef(values_list_id=701)))
    assert [(i.id, i.raw["depth"]) for i in out.items] == [(9001, 0), (9002, 1), (9003, 0)]


def test_discover_content_api():
    routes = base_routes()
    routes[("GET", "/contentapi/")] = {"status": 200, "json": {"openapi": "3.0.0"}}
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.discover_content_api(EmptyInput()))
    assert out.available is True and out.status == 200


def test_search_content():
    routes = base_routes()
    routes[("POST", "/platformapi/core/system/fielddefinition/level/401")] = {
        "json": fixture(CLIENT, "fields_level.json")
    }
    routes[("POST", "/ws/search.asmx")] = {"text": (CLIENT / "soap_search.xml").read_text(encoding="utf-8")}
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.search_content(SearchContentArgs(level_id=401, page_size=2)))
    assert [r.id for r in out.records] == [1001, 1002]
    assert out.page_number == 1
    assert out.has_more is True
    assert out.records[0].raw["fields"]["Title"] == "Risk A"


def test_get_content_maps_fields_and_version():
    routes = base_routes()
    routes[("POST", "/platformapi/core/content/contentid")] = {"json": fixture(OPS, "content.json")}
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.get_content(ContentRef(content_id=1001)))
    content = out.content
    assert content.content_id == 1001
    assert content.level_id == 401
    assert content.version == 7
    assert content.fields["5001"] == "Risk A"
    assert content.fields["5003"] == {"ValuesListIds": [9001]}
    assert content.fields["5009"] == "10.0.0.1"


def test_get_record_soap():
    routes = base_routes()
    routes[("POST", "/ws/record.asmx")] = {"text": (OPS / "soap_record.xml").read_text(encoding="utf-8")}
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.get_record_soap(ContentRef(content_id=1001)))
    assert out.content.content_id == 1001
    assert out.content.fields["5001"] == "Risk A"
    assert out.content.fields["5002"] == "2026-01-02T03:04:05Z"


def test_get_history():
    routes = base_routes()
    routes[("POST", "/platformapi/core/content/history/1001")] = {"json": fixture(OPS, "history.json")}
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.get_history(ContentRef(content_id=1001)))
    assert out.entries[0]["Version"] == 6


def test_get_attachment_bytes_sha256_and_base64():
    payload = b"archer-attachment-bytes"
    routes = base_routes()
    routes[("POST", "/platformapi/core/content/attachment/77")] = {"text": payload.decode("ascii")}
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.get_attachment(AttachmentRef(attachment_id=77)))
    assert out.size_bytes == len(payload)
    assert out.sha256 == hashlib.sha256(payload).hexdigest()
    assert base64.b64decode(out.content_base64) == payload


def test_get_attachment_rejects_oversize():
    routes = base_routes()
    routes[("POST", "/platformapi/core/content/attachment/77")] = {"text": "x" * 100}
    connector = make_archer(RouteTransport(routes), config_overrides={"attachment_max_bytes": 10})
    with pytest.raises(BudgetExhausted):
        asyncio.run(connector.get_attachment(AttachmentRef(attachment_id=77)))


def test_get_data_feed_history():
    routes = base_routes()
    routes[("POST", "/platformapi/core/datafeed/history")] = {
        "json": fixture(OPS, "data_feed_history.json")
    }
    connector = make_archer(RouteTransport(routes))
    out = asyncio.run(connector.get_data_feed_history(EmptyInput()))
    assert out.runs[0]["Guid"] == "df-1"


def test_unsuccessful_envelope_raises():
    routes = base_routes()
    routes[("POST", "/platformapi/core/content/contentid")] = {
        "json": {"IsSuccessful": False, "ValidationMessages": [{"ResourcedMessage": "denied"}]}
    }
    connector = make_archer(RouteTransport(routes))
    with pytest.raises(VendorContractError):
        asyncio.run(connector.get_content(ContentRef(content_id=1001)))
