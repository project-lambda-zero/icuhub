"""Archer connector tests: conformance, health, discovery, manifest, config."""

import asyncio
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from icuhub.connectors.archer import Archer
from icuhub.connectors.archer.models import ArcherConfig
from icuhub.kit import VendorContractError, build_manifest, conformance_problems

from .conftest import RouteTransport, make_archer

FIXTURES = Path(__file__).parents[2] / "fixtures" / "archer" / "client"
LOGIN = ("POST", "/platformapi/core/security/login")
APP_INFO = ("POST", "/platformapi/core/system/applicationinfo/version")
APPLICATIONS = ("POST", "/platformapi/core/system/application")
CONTENT_API = ("GET", "/contentapi/")
MANIFEST = Path(__file__).parents[3] / "src" / "icuhub" / "connectors" / "archer" / "manifest.json"


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def healthy_routes():
    return {
        LOGIN: {"json": fixture("login.json")},
        APP_INFO: {"json": fixture("app_info.json")},
        APPLICATIONS: {"json": [fixture("applications.json")[0]]},
        CONTENT_API: {"status": 404, "text": "not found"},
    }


def test_conformance_and_manifest():
    assert conformance_problems(Archer) == []
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest == build_manifest(Archer)
    action_names = {a["name"] for a in manifest["actions"]}
    assert action_names == {
        "create_finding_or_exception",
        "update_finding_or_exception",
        "upload_attachment",
        "execute_data_feed",
        "delete_content",
    }
    stream_names = {s["name"] for s in manifest["streams"]}
    assert stream_names == set(Archer.streams())
    assert set(manifest["auth"]) == {"SessionLogin"}


def test_config_domain_session_requires_user_domain():
    with pytest.raises(ValidationError):
        ArcherConfig.model_validate(
            {
                "base_url": "https://archer.example.test",
                "instance_name": "default",
                "auth_mode": "domain_session",
                "user": "api-user",
                "password": {"ref": "vault:archer-password"},
            }
        )


def test_check_healthy_and_content_api_not_evaluated():
    connector = make_archer(RouteTransport(healthy_routes()))
    report = asyncio.run(connector.check())
    assert report.status == "healthy"
    assert report.vendor_version == "2025.10"
    assert report.capabilities["version"].status == "healthy"
    assert report.capabilities["metadata"].status == "healthy"
    assert report.capabilities["content_api"].status == "not_evaluated"
    assert report.capabilities["RiskRegister"].status == "healthy"


def test_check_permission_denied_is_not_evaluated_not_closed():
    routes = healthy_routes()
    routes[APPLICATIONS] = {"status": 403, "json": {"IsSuccessful": False}}
    connector = make_archer(RouteTransport(routes))
    report = asyncio.run(connector.check())
    assert report.status == "degraded"
    assert report.capabilities["metadata"].status == "not_evaluated"


def test_check_auth_failure_is_failing():
    routes = healthy_routes()
    routes[LOGIN] = {"json": fixture("login_denied.json")}
    connector = make_archer(RouteTransport(routes))
    report = asyncio.run(connector.check())
    assert report.status == "failing"
    assert report.capabilities["RiskRegister"].status == "failing"


def test_discover_refuses_permission_filtered_applications():
    routes = healthy_routes()
    routes[APPLICATIONS] = {"json": fixture("applications.json")}
    connector = make_archer(RouteTransport(routes))

    async def collect():
        return [record async for record in connector.discover()]

    with pytest.raises(VendorContractError, match="refused"):
        asyncio.run(collect())


def test_no_webhook_verifier():
    connector = make_archer(RouteTransport(healthy_routes()))
    assert connector.webhook_verifier(b"secret") is None
    assert Archer.webhooks() == {}
