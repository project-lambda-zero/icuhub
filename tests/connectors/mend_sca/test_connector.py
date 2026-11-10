"""Mend SCA connector tests: conformance, manifest, health, configuration, unknown streams."""

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from icuhub.connectors.mend_sca.connector import MendSca
from icuhub.connectors.mend_sca.models import MendSCAConfig
from icuhub.kit import build_manifest, conformance_problems
from icuhub.kit.testing import collect_stream

from .conftest import BASE_CONFIG, ORG_UUID, SECRETS, make_mend

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
