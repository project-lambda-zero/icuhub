"""Mend SCA connector tests: conformance, manifest, health, configuration, unknown streams."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from icuhub.connectors.mend_sca.connector import MendSca
from icuhub.connectors.mend_sca.models import MendSCAConfig
from icuhub.kit import build_manifest, conformance_problems
from icuhub.kit import testing as kit_testing
from icuhub.kit.testing import collect_stream

from .conftest import BASE_CONFIG, ORG_UUID, REFRESH, SECRETS, RouteTransport, make_mend

FIXTURES = Path(__file__).parents[2] / "fixtures" / "mend_sca"
MANIFEST = Path(__file__).parents[3] / "src" / "icuhub" / "connectors" / "mend_sca" / "manifest.json"
PROJECTS_V3 = ("GET", f"/api/v3.0/orgs/{ORG_UUID}/projects")
PROJECTS_V2 = ("GET", "/api/v2.0/projects")
V2_LOGIN = ("POST", "/api/v2.0/login")
V2_CONFIG: dict[str, Any] = {
    "api_version": "2.0",
    "org_uuid": None,
    "org_token": {"ref": "vault:mend-org-token"},
}
V2_SECRETS = {**SECRETS, "vault:mend-org-token": b"test-org-token"}


def fixture(rel: str) -> Any:
    return json.loads((FIXTURES / rel).read_text(encoding="utf-8"))


def test_conformance_and_manifest_match_class() -> None:
    assert conformance_problems(MendSca) == []
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest == build_manifest(MendSca)
    assert {scope.name for scope in MendSca.scopes} == {"projects", "security_findings", "security_alerts", "write"}
    assert MendSca.capabilities == ("FindingSource",)
    assert {stream["name"] for stream in manifest["streams"]} == set(MendSca.streams())
    assert set(manifest["auth"]) == {"SessionLogin"}


def test_check_reports_healthy_when_v3_project_listing_succeeds() -> None:
    connector = make_mend({PROJECTS_V3: {"json": fixture("v3/projects_page1.json")}})
    report = asyncio.run(connector.check())
    assert report.status == "healthy"
    assert report.capabilities["FindingSource"].status == "healthy"
    assert report.vendor_version == "3.0"


def test_check_reports_healthy_when_v2_project_listing_succeeds() -> None:
    connector = make_mend(
        {
            V2_LOGIN: {"json": fixture("v2/login.json")},
            PROJECTS_V2: {"json": {"retVal": [], "additionalData": {"isLastPage": True}}},
        },
        config_overrides=V2_CONFIG,
        secrets=V2_SECRETS,
    )
    report = asyncio.run(connector.check())
    assert report.status == "healthy"
    assert report.vendor_version == "2.0"


def test_check_reports_failing_when_probe_rejects_credentials() -> None:
    connector = make_mend({PROJECTS_V3: {"status": 401, "json": {"errorMessage": "Unauthorized"}}})
    report = asyncio.run(connector.check())
    assert report.status == "failing"
    assert report.capabilities["FindingSource"].status == "failing"
    assert report.capabilities["FindingSource"].reason == "AuthFailed"


def test_check_reports_degraded_when_project_listing_is_forbidden() -> None:
    connector = make_mend({PROJECTS_V3: {"status": 403, "json": fixture("denied/projects_access_denied.json")}})
    report = asyncio.run(connector.check())
    assert report.status == "degraded"
    assert report.capabilities["FindingSource"].status == "not_evaluated"
    assert report.capabilities["FindingSource"].reason == "PermissionDenied"


def test_v3_configuration_defaults_to_write_disabled() -> None:
    cfg = MendSCAConfig.model_validate(BASE_CONFIG)
    assert cfg.api_version == "3.0"
    assert cfg.write_enabled is False


def test_v2_configuration_accepts_org_token_without_org_uuid() -> None:
    cfg = MendSCAConfig.model_validate({**BASE_CONFIG, **V2_CONFIG})
    assert cfg.api_version == "2.0"
    assert cfg.org_uuid is None


def test_v3_configuration_requires_org_uuid() -> None:
    with pytest.raises(ValidationError):
        MendSCAConfig.model_validate({**BASE_CONFIG, "org_uuid": None, "org_token": {"ref": "vault:mend-org-token"}})


def test_unknown_stream_is_rejected() -> None:
    connector = make_mend({})
    with pytest.raises(ValueError):
        collect_stream(connector, "no_such_stream")


# -- 3.0 session lifecycle -------------------------------------------------
# Login and refresh shapes: https://api-docs.mend.io/platform/3.0/access-management/login.md and
# https://api-docs.mend.io/platform/3.0/access-management/refreshaccesstoken.md. The session clock is the kit
# seam (``kit.testing._fixed_clock``), patched per test so the 1800 s access-token TTL can be crossed.

REFRESH_PATH = "/api/v3.0/login/accessToken"
LOGIN_PATH = "/api/v3.0/login"
PROBE_PATH = f"/api/v3.0/orgs/{ORG_UUID}/projects"
PROBE_ROUTE = ("GET", PROBE_PATH)


@pytest.fixture
def session_clock(monkeypatch: pytest.MonkeyPatch) -> dict[str, datetime]:
    now = {"t": datetime(2026, 11, 10, 12, 0, tzinfo=UTC)}
    monkeypatch.setattr(kit_testing, "_fixed_clock", lambda: now["t"])
    return now


def _count(transport: RouteTransport, path: str) -> int:
    return sum(1 for request in transport.requests if request.url.path == path)


def _scripted_refresh(*statuses: int) -> Any:
    """Access-token route answering the scripted statuses in order; 200 issues a fresh ``jwt-N``."""
    remaining = list(statuses)
    issued = {"n": 0}

    def handler(_request: Any) -> dict[str, Any]:
        status = remaining.pop(0)
        if status != 200:
            return {"status": status, "json": {"errorMessage": "Unauthorized"}}
        issued["n"] += 1
        return {"json": {"response": {"orgUuid": ORG_UUID, "jwtToken": f"jwt-{issued['n']}", "tokenTTL": 1800}}}

    return handler


def test_expired_session_is_renewed_through_refresh_token_exchange(session_clock: dict[str, datetime]) -> None:
    transport = RouteTransport({PROBE_ROUTE: {"json": {"response": []}}})
    connector = make_mend(transport)

    async def scenario() -> None:
        await connector.call("GET", PROBE_PATH)
        session_clock["t"] += timedelta(seconds=1801)
        await connector.call("GET", PROBE_PATH)

    asyncio.run(scenario())

    assert _count(transport, LOGIN_PATH) == 1
    assert _count(transport, REFRESH_PATH) == 2
    refresh = [request for request in transport.requests if request.url.path == REFRESH_PATH][-1]
    assert refresh.headers["wss-refresh-token"] == "example-refresh"
    assert refresh.url.params["orgUuid"] == ORG_UUID
    assert transport.requests[-1].headers["Authorization"] == "Bearer example-jwt"


def test_rejected_refresh_token_falls_back_to_full_login(session_clock: dict[str, datetime]) -> None:
    transport = RouteTransport(
        {
            PROBE_ROUTE: {"json": {"response": []}},
            REFRESH: _scripted_refresh(200, 401, 200),
        }
    )
    connector = make_mend(transport)

    async def scenario() -> None:
        await connector.call("GET", PROBE_PATH)
        session_clock["t"] += timedelta(seconds=1801)
        await connector.call("GET", PROBE_PATH)

    asyncio.run(scenario())

    assert _count(transport, LOGIN_PATH) == 2
    assert _count(transport, REFRESH_PATH) == 3
    assert transport.requests[-1].headers["Authorization"] == "Bearer jwt-2"


def test_concurrent_callers_on_expired_session_issue_one_refresh(session_clock: dict[str, datetime]) -> None:
    transport = RouteTransport({PROBE_ROUTE: {"json": {"response": []}}})
    connector = make_mend(transport)

    async def scenario() -> None:
        await connector.call("GET", PROBE_PATH)
        session_clock["t"] += timedelta(seconds=1801)
        await asyncio.gather(*(connector.call("GET", PROBE_PATH) for _ in range(8)))

    asyncio.run(scenario())

    assert _count(transport, LOGIN_PATH) == 1
    assert _count(transport, REFRESH_PATH) == 2


def test_full_v3_login_sends_only_email_and_user_key(session_clock: dict[str, datetime]) -> None:
    transport = RouteTransport({PROBE_ROUTE: {"json": {"response": []}}})
    connector = make_mend(transport)

    asyncio.run(connector.call("GET", PROBE_PATH))

    login = [request for request in transport.requests if request.url.path == LOGIN_PATH]
    assert len(login) == 1
    assert json.loads(login[0].content) == {"email": BASE_CONFIG["email"], "userKey": "test-user-key"}
