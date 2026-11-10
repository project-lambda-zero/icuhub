"""Archer client tests: login, envelopes, SOAP, encoding, bounded downloads."""

import asyncio
import json
from pathlib import Path

import pytest

from icuhub.kit import AuthFailed, BudgetExhausted, ConfigError, VendorContractError

from .conftest import RouteTransport, make_archer

FIXTURES = Path(__file__).parents[2] / "fixtures" / "archer" / "client"
LOGIN = ("POST", "/platformapi/core/security/login")
APP_INFO = ("POST", "/platformapi/core/system/applicationinfo")
SEARCH = ("POST", "/ws/search.asmx")


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_rest_login_and_post_get_override():
    seen = {}

    def login(request):
        seen["login_body"] = json.loads(request.content)
        return {"json": fixture("login.json")}

    def app_info(request):
        seen["auth"] = request.headers.get("authorization")
        seen["override"] = request.headers.get("x-http-method-override")
        return {"json": fixture("app_info.json")}

    connector = make_archer(RouteTransport({LOGIN: login, APP_INFO: app_info}))
    version = asyncio.run(connector.api.version())
    assert version.version == "2025.10"
    assert seen["login_body"] == {
        "InstanceName": "default",
        "Username": "api-user",
        "UserDomain": "",
        "Password": "test-password",
    }
    assert seen["auth"] == 'Archer session-id="tok-1"'
    assert seen["override"] == "GET"


def test_login_rejected_raises_auth_failed():
    connector = make_archer(
        RouteTransport({LOGIN: {"json": fixture("login_denied.json")}})
    )
    with pytest.raises(AuthFailed):
        asyncio.run(connector.api.version())


def test_401_triggers_single_login_refresh():
    calls = {"login": 0, "app_info": 0, "tokens": []}

    def login(request):
        calls["login"] += 1
        return {"json": {"IsSuccessful": True, "RequestedObject": {"SessionToken": f"tok-{calls['login']}"}}}

    def app_info(request):
        calls["app_info"] += 1
        calls["tokens"].append(request.headers.get("authorization"))
        if calls["app_info"] == 1:
            return {"status": 401, "json": {"IsSuccessful": False}}
        return {"json": fixture("app_info.json")}

    connector = make_archer(RouteTransport({LOGIN: login, APP_INFO: app_info}))
    version = asyncio.run(connector.api.version())
    assert version.version == "2025.10"
    assert calls["login"] == 2
    assert calls["tokens"] == ['Archer session-id="tok-1"', 'Archer session-id="tok-2"']


def test_unsuccessful_envelope_raises_contract_error():
    routes = {
        LOGIN: {"json": fixture("login.json")},
        APP_INFO: {"json": {"IsSuccessful": False, "ValidationMessages": [{"ResourcedMessage": "denied"}]}},
    }
    connector = make_archer(RouteTransport(routes))
    with pytest.raises(VendorContractError):
        asyncio.run(connector.api.version())


def test_permission_filtered_list_items_are_omitted():
    routes = {
        LOGIN: {"json": fixture("login.json")},
        ("POST", "/platformapi/core/system/application"): {"json": fixture("applications.json")},
    }
    connector = make_archer(RouteTransport(routes))
    apps = asyncio.run(connector.api.applications())
    assert [a["Id"] for a in apps] == [301]


def test_encode_fields_resolves_values_list_names():
    routes = {
        LOGIN: {"json": fixture("login.json")},
        ("POST", "/platformapi/core/system/fielddefinition/level/401"): {"json": fixture("fields_level.json")},
        ("POST", "/platformapi/core/system/valueslistvalue/valueslist/701"): {"json": fixture("values_list.json")},
    }
    connector = make_archer(RouteTransport(routes))
    encoded = asyncio.run(connector.api.encode_fields(401, {"Title": "Risk A", "Status": "Open"}))
    assert encoded["5001"] == {"Type": 1, "Value": "Risk A", "FieldId": 5001}
    assert encoded["5003"]["Value"] == {"ValuesListIds": [9001]}
    assert encoded["5003"]["Type"] == 4
    with pytest.raises(ConfigError):
        asyncio.run(connector.api.encode_fields(401, {"Status": "Not A Status"}))
    with pytest.raises(ConfigError):
        asyncio.run(connector.api.encode_fields(401, {"No Such Field": 1}))


def test_soap_search_uses_body_token_and_parses_fields():
    seen = {}

    def search(request):
        seen["body"] = request.content.decode("utf-8")
        seen["soap_action"] = request.headers.get("soapaction")
        return {"text": fixture_text("soap_search.xml")}

    routes = {LOGIN: {"json": fixture("login.json")}, SEARCH: search}
    connector = make_archer(RouteTransport(routes))
    records = asyncio.run(
        connector.api.search_records(
            level_id=401,
            application_id=301,
            display_fields={"Title": 5001, "LastUpdated": 5002, "Status": 5003},
        )
    )
    assert "<sessionToken>tok-1</sessionToken>" in seen["body"]
    assert "SearchReport" in seen["body"]
    assert '<DisplayField name="Title">5001</DisplayField>' in seen["body"]
    assert seen["soap_action"] == "http://archer-tech.com/webservices/ExecuteSearch"
    assert len(records) == 2
    first = records[0]
    assert first["content_id"] == 1001
    assert first["fields"]["Title"] == "Risk A"
    assert first["fields"]["LastUpdated"] == "2026-01-02T03:04:05Z"
    assert first["fields"]["Status"] == ["Open"]


def test_soap_500_regenerates_token_once():
    calls = {"login": 0, "search": 0}

    def login(request):
        calls["login"] += 1
        return {"json": {"IsSuccessful": True, "RequestedObject": {"SessionToken": f"tok-{calls['login']}"}}}

    def search(request):
        calls["search"] += 1
        if calls["search"] == 1:
            return {"status": 500, "text": "server error"}
        return {"text": fixture_text("soap_search.xml")}

    connector = make_archer(RouteTransport({LOGIN: login, SEARCH: search}))
    records = asyncio.run(connector.api.search_records(level_id=401, application_id=301))
    assert len(records) == 2
    assert calls["login"] == 2
    assert calls["search"] == 2


def test_soap_fault_raises_contract_error():
    routes = {
        LOGIN: {"json": fixture("login.json")},
        SEARCH: {"text": fixture_text("soap_fault.xml")},
    }
    connector = make_archer(RouteTransport(routes))
    with pytest.raises(VendorContractError):
        asyncio.run(connector.api.search_records(level_id=401, application_id=301))


def test_domain_login_uses_soap_and_users_domain():
    seen = {}

    def general(request):
        seen["body"] = request.content.decode("utf-8")
        seen["soap_action"] = request.headers.get("soapaction")
        return {"text": fixture_text("soap_domain_login.xml")}

    routes = {
        ("POST", "/ws/general.asmx"): general,
        APP_INFO: {"json": fixture("app_info.json")},
    }
    connector = make_archer(
        RouteTransport(routes),
        config_overrides={"auth_mode": "domain_session", "user_domain": "EXAMPLE"},
    )
    version = asyncio.run(connector.api.version())
    assert version.version == "2025.10"
    assert "CreateDomainUserSessionFromInstance" in seen["body"]
    assert "<usersDomain>EXAMPLE</usersDomain>" in seen["body"]
    assert "<sessionToken>" not in seen["body"]
    assert seen["soap_action"] == "http://archer-tech.com/webservices/CreateDomainUserSessionFromInstance"


def test_attachment_download_is_bounded():
    routes = {
        LOGIN: {"json": fixture("login.json")},
        ("POST", "/platformapi/core/content/attachment/77"): {"text": "x" * 100},
    }
    connector = make_archer(RouteTransport(routes), config_overrides={"attachment_max_bytes": 10})
    with pytest.raises(BudgetExhausted):
        asyncio.run(connector.api.attachment_bytes(77))
