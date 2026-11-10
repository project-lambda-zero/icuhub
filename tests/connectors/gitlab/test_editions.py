"""Edition contract tests for GitLab.com and GitLab Self-Managed."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import ValidationError

from icuhub.connectors._gitlab.models import SelfManagedGitLabConfig
from icuhub.connectors.gitlab import GitLab
from icuhub.connectors.gitlab.models import GitLabComConfig
from icuhub.connectors.gitlab_self_managed import GitLabSelfManaged
from icuhub.kit.errors import PermissionDenied
from icuhub.kit.testing import RouteTransport, conformance_problems, make_connector

API = "/api/v4"
TOKEN_REF = "gitlab_token"
SECRETS = {TOKEN_REF: b"not-a-real-token"}
SELF_MANAGED_BASE = "https://gitlab.example.test/api/v4"


def _routes(version: Any = None) -> dict[tuple[str, str], Any]:
    routes: dict[tuple[str, str], Any] = {
        ("GET", f"{API}/user"): {"status": 200, "json": {"id": 7}},
        ("GET", f"{API}/license"): {"status": 200, "json": {"plan": "ultimate"}},
        ("GET", f"{API}/audit_events"): {"status": 200, "json": []},
    }
    if version is not None:
        routes[("GET", f"{API}/version")] = version
    return routes


def _self_managed(routes: dict[tuple[str, str], Any]) -> GitLabSelfManaged:
    config = {"base_url": SELF_MANAGED_BASE, "access_token": {"ref": TOKEN_REF}}
    return make_connector(GitLabSelfManaged, config, RouteTransport(routes), SECRETS)  # type: ignore[return-value]


# GitLab.com


def test_gitlab_com_identity_and_flows() -> None:
    assert GitLab.kind == "gitlab"
    assert GitLab.flows == ("F-022", "F-201")
    assert GitLab.config_model is GitLabComConfig


def test_gitlab_com_conforms() -> None:
    assert conformance_problems(GitLab) == []


def test_gitlab_com_accepts_gitlab_com_root() -> None:
    config = GitLabComConfig(access_token={"ref": TOKEN_REF})  # type: ignore[arg-type]
    assert config.base_url == "https://gitlab.com/api/v4"


@pytest.mark.parametrize(
    "base_url",
    ["https://gitlab.example.test/api/v4", "https://evilgitlab.com/api/v4", "https://gitlab.com.evil.test/api/v4"],
)
def test_gitlab_com_rejects_other_hosts(base_url: str) -> None:
    with pytest.raises(ValidationError, match="gitlab.com API root"):
        GitLabComConfig(base_url=base_url, access_token={"ref": TOKEN_REF})  # type: ignore[arg-type]


# GitLab Self-Managed


def test_self_managed_identity_and_flows() -> None:
    assert GitLabSelfManaged.kind == "gitlab_self_managed"
    assert GitLabSelfManaged.flows == ("F-027", "F-101")


def test_self_managed_accepts_private_ca_bundle() -> None:
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    config = SelfManagedGitLabConfig.model_validate(
        {"base_url": SELF_MANAGED_BASE, "access_token": {"ref": TOKEN_REF}, "ca_bundle_pem": pem}
    )
    assert config.ca_bundle_pem == pem


def test_self_managed_conforms() -> None:
    assert conformance_problems(GitLabSelfManaged) == []


def test_self_managed_check_reports_instance_version() -> None:
    connector = _self_managed(_routes({"status": 200, "json": {"version": "17.4.1", "revision": "abc"}}))
    report = asyncio.run(connector.check())
    assert report.vendor_version == "17.4.1"
    assert report.status == "healthy"


def test_self_managed_check_degrades_when_version_is_malformed() -> None:
    connector = _self_managed(_routes({"status": 200, "json": {"revision": "abc"}}))
    report = asyncio.run(connector.check())
    assert report.vendor_version is None
    assert report.status == "degraded"
    assert report.detail["version_error"] == "VendorContractError"


def test_self_managed_check_marks_ultimate_capabilities_healthy_only_on_ultimate_plan() -> None:
    connector = _self_managed(_routes({"status": 200, "json": {"version": "19.1.0"}}))
    report = asyncio.run(connector.check())
    assert report.capabilities["FindingSource"].status == "healthy"
    assert report.capabilities["CodeScanningSink"].status == "healthy"

    routes = _routes({"status": 200, "json": {"version": "19.1.0"}})
    routes[("GET", f"{API}/license")] = {"status": 200, "json": {"plan": "premium"}}
    report = asyncio.run(_self_managed(routes).check())
    assert report.capabilities["FindingSource"].status == "not_evaluated"
    assert report.capabilities["FindingSource"].reason == "PlanNotUltimate"
    assert report.capabilities["CodeScanningSink"].status == "not_evaluated"


def test_self_managed_check_reports_standard_webhooks_by_version() -> None:
    old = asyncio.run(_self_managed(_routes({"status": 200, "json": {"version": "18.9.2"}})).check())
    assert old.detail["standard_webhooks"] == "not_evaluated"
    new = asyncio.run(_self_managed(_routes({"status": 200, "json": {"version": "19.1.0"}})).check())
    assert new.detail["standard_webhooks"] == "available"


def test_self_managed_check_reports_audit_events_state() -> None:
    report = asyncio.run(_self_managed(_routes({"status": 200, "json": {"version": "19.1.0"}})).check())
    assert report.detail["audit_events"] == "available"

    routes = _routes({"status": 200, "json": {"version": "19.1.0"}})
    routes[("GET", f"{API}/audit_events")] = {"status": 403, "json": {"message": "403 Forbidden"}}
    report = asyncio.run(_self_managed(routes).check())
    assert report.detail["audit_events"] == "not_evaluated:PermissionDenied"


def test_self_managed_check_reports_configured_trust_root() -> None:
    connector = _self_managed(_routes({"status": 200, "json": {"version": "19.1.0"}}))
    report = asyncio.run(connector.check())
    assert report.detail["ca_bundle"] == "system_trust"


def test_require_ultimate_rejects_non_ultimate_namespace_plan() -> None:
    routes = _routes({"status": 200, "json": {"version": "19.1.0"}})
    routes[("GET", f"{API}/license")] = {"status": 200, "json": {"plan": "free"}}
    with pytest.raises(PermissionDenied):
        asyncio.run(_self_managed(routes).require_ultimate(5))
