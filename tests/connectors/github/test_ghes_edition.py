"""Connector-level tests for the GitHub Enterprise Server edition.

Covers the GHES config root rules (self-hosted host, ``/api/v3`` REST root), the health check's
``/meta`` version probe (``X-GitHub-Enterprise-Version``, degraded on missing header or probe
failure), the repository stream on the self-hosted root, the pull request and code scanning
mappers, and the HMAC webhook verifier with ``code_scanning_alert`` hint parsing. Requests are
answered by ``RouteTransport`` from the synthetic fixtures in
``tests/fixtures/github_enterprise_server/``.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx2
import pytest

from icuhub.connectors._github.webhooks import hints_for_delivery
from icuhub.connectors.github_enterprise_server import GitHubEnterpriseServer
from icuhub.connectors.github_enterprise_server.models import GitHubEnterpriseServerConfig
from icuhub.kit.errors import VendorContractError, WebhookRejected
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import Target, WebhookDelivery
from icuhub_schemas.ocsf import VulnerabilityFinding

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "github_enterprise_server"
BASE = "https://ghes.example.test/api/v3"
PAT_REF = "github-pat"
SECRETS = {PAT_REF: b"synthetic-pat"}
HMAC_SECRET = b"synthetic-webhook-secret"
NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
GHES_VERSION = "3.14.0"
RATE_LIMIT_PATH = "/api/v3/rate_limit"
META_PATH = "/api/v3/meta"
REPOSITORIES_PATH = "/api/v3/user/repos"
TARGET = Target(
    id="1001",
    source_uid="1001",
    kind="repository",
    display_name="example-org/example-repo",
    attributes={"owner": "example-org", "repo": "example-repo"},
)


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _connector(routes: dict[tuple[str, str], Any]) -> GitHubEnterpriseServer:
    config = {"base_url": BASE, "personal_access_token": {"ref": PAT_REF}}
    return cast(GitHubEnterpriseServer, make_connector(GitHubEnterpriseServer, config, RouteTransport(routes), SECRETS))


def _meta_ok() -> dict[str, Any]:
    return {"status": 200, "json": _load("ghes_meta.json"), "headers": {"X-GitHub-Enterprise-Version": GHES_VERSION}}


def _delivery(body: bytes, headers: dict[str, str]) -> WebhookDelivery:
    return WebhookDelivery(headers=headers, body=body, received_at=NOW)


def _signature(body: bytes, secret: bytes = HMAC_SECRET) -> dict[str, str]:
    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return {"x-hub-signature-256": f"sha256={digest}"}


def _paged_repositories(requests: list[httpx2.Request]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(request: httpx2.Request) -> dict[str, Any]:
        requests.append(request)
        if request.url.params.get("page") == "2":
            return {"status": 200, "json": _load("repositories_page2.json")}
        next_url = f"{BASE}/user/repos?visibility=all&sort=full_name&direction=asc&per_page=100&page=2"
        return {
            "status": 200,
            "json": _load("repositories_page1.json"),
            "headers": {"link": f'<{next_url}>; rel="next"'},
        }

    return handler


# --- config -----------------------------------------------------------------


def test_config_accepts_self_hosted_api_v3_root() -> None:
    config = GitHubEnterpriseServerConfig.model_validate({"base_url": BASE, "personal_access_token": {"ref": PAT_REF}})

    assert config.base_url == BASE


def test_config_rejects_github_com_host() -> None:
    with pytest.raises(ValueError, match="self-hosted"):
        GitHubEnterpriseServerConfig.model_validate(
            {"base_url": "https://api.github.com", "personal_access_token": {"ref": PAT_REF}}
        )


def test_config_requires_api_v3_path() -> None:
    with pytest.raises(ValueError, match="/api/v3"):
        GitHubEnterpriseServerConfig.model_validate(
            {"base_url": "https://ghes.example.test", "personal_access_token": {"ref": PAT_REF}}
        )


# --- health: /meta version probe ---------------------------------------------


def test_health_records_ghes_version_from_meta_header() -> None:
    connector = _connector({
        ("GET", RATE_LIMIT_PATH): {"status": 200, "json": _load("rate_limit.json")},
        ("GET", META_PATH): _meta_ok(),
    })

    report = asyncio.run(connector.check())

    assert report.status == "healthy"
    assert report.vendor_version == GHES_VERSION
    assert report.detail["ghes_version"] == GHES_VERSION
    assert "ghes_version_error" not in report.detail


def test_missing_version_header_degrades_health() -> None:
    connector = _connector({
        ("GET", RATE_LIMIT_PATH): {"status": 200, "json": _load("rate_limit.json")},
        ("GET", META_PATH): {"status": 200, "json": _load("ghes_meta.json")},
    })

    report = asyncio.run(connector.check())

    assert report.status == "degraded"
    assert report.vendor_version is None
    assert "ghes_version" not in report.detail
    assert report.detail["ghes_version_error"] == "VendorContractError"


def test_meta_endpoint_not_found_degrades_health() -> None:
    connector = _connector({
        ("GET", RATE_LIMIT_PATH): {"status": 200, "json": _load("rate_limit.json")},
        ("GET", META_PATH): {"status": 404, "json": {"message": "Not Found"}},
    })

    report = asyncio.run(connector.check())

    assert report.status == "degraded"
    assert "ghes_version" not in report.detail
    assert report.detail["ghes_version_error"] == "NotFound"


def test_forbidden_meta_probe_degrades_health_with_permission_denied() -> None:
    connector = _connector({
        ("GET", RATE_LIMIT_PATH): {"status": 200, "json": _load("rate_limit.json")},
        ("GET", META_PATH): {"status": 403, "json": _load("probe_forbidden.json")},
    })

    report = asyncio.run(connector.check())

    assert report.status == "degraded"
    assert "ghes_version" not in report.detail
    assert report.detail["ghes_version_error"] == "PermissionDenied"


def test_failing_base_check_stays_failing_and_still_records_version() -> None:
    connector = _connector({
        ("GET", RATE_LIMIT_PATH): {"status": 401, "json": {"message": "Bad credentials"}},
        ("GET", META_PATH): _meta_ok(),
    })

    report = asyncio.run(connector.check())

    assert report.status == "failing"
    assert report.detail["ghes_version"] == GHES_VERSION


# --- repositories stream on the self-hosted root -----------------------------


def test_repositories_stream_follows_link_header_pages() -> None:
    requests: list[httpx2.Request] = []
    connector = _connector({("GET", REPOSITORIES_PATH): _paged_repositories(requests)})

    batches = collect_stream(connector, "repositories", mode="full")

    names = [record["name"] for batch in batches for record in batch.records]
    assert names == ["example-repo", "example-repo-2"]
    assert requests[0].url.params.get("visibility") == "all"
    assert requests[1].url.params.get("page") == "2"


def test_non_object_repository_record_is_a_contract_violation() -> None:
    connector = _connector({("GET", REPOSITORIES_PATH): {"status": 200, "json": _load("repository_malformed.json")}})

    with pytest.raises(VendorContractError, match="non-object record"):
        collect_stream(connector, "repositories", mode="full")


# --- mappers ----------------------------------------------------------------


def test_repository_maps_to_source_record_with_raw_evidence() -> None:
    connector = _connector({})

    (record,) = map_all(connector, "repositories", [_load("repository.json")])

    assert record.data["stream"] == "repositories"
    assert json.loads(record.data["raw"])["full_name"] == "example-org/example-repo"


def test_repository_unknown_fields_are_preserved_in_raw_evidence() -> None:
    connector = _connector({})

    (record,) = map_all(connector, "repositories", [_load("repository_unknown_fields.json")])

    raw = json.loads(record.data["raw"])
    assert raw["x_synthetic_future_field"] == "keep-me"
    assert raw["x_synthetic_future_object"] == {"schema_version": 2, "flags": ["alpha"]}


def test_open_pull_request_maps_to_open_ticket() -> None:
    connector = _connector({})
    raw = _load("pull_request_open.json")
    raw["_repository_id"] = 1001

    (ticket,) = map_all(connector, "pull_requests", [raw], target=TARGET)

    assert ticket.key == "#7"
    assert ticket.status == "open"
    assert ticket.status_category == "open"
    assert ticket.resolution is None


def test_code_scanning_alert_maps_to_vulnerability_finding() -> None:
    connector = _connector({})
    raw = _load("code_scanning_alert.json")
    raw["_repository_id"] = 1001

    (finding,) = map_all(connector, "code_scanning_alerts", [raw], target=TARGET)

    assert isinstance(finding, VulnerabilityFinding)


# --- webhooks ---------------------------------------------------------------


def test_signed_code_scanning_delivery_verifies() -> None:
    connector = _connector({})
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None
    headers = {
        **_signature(body),
        "x-github-event": "code_scanning_alert",
        "x-github-delivery": "delivery-ghes-1",
    }

    verified = verifier.verify(_delivery(body, headers), now=NOW)

    assert verified.delivery_id == "delivery-ghes-1"
    assert verified.event_type == "code_scanning_alert"


def test_delivery_with_wrong_signature_is_rejected() -> None:
    connector = _connector({})
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None
    headers = {
        **_signature(body, secret=b"other-secret"),
        "x-github-event": "code_scanning_alert",
        "x-github-delivery": "delivery-ghes-2",
    }

    with pytest.raises(WebhookRejected):
        verifier.verify(_delivery(body, headers), now=NOW)


def test_legacy_sha1_signature_is_rejected() -> None:
    connector = _connector({})
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None
    digest = hmac.new(HMAC_SECRET, body, hashlib.sha1).hexdigest()
    headers = {
        "x-hub-signature": f"sha1={digest}",
        "x-github-event": "code_scanning_alert",
        "x-github-delivery": "delivery-ghes-3",
    }

    with pytest.raises(WebhookRejected, match="missing webhook header: x-hub-signature-256"):
        verifier.verify(_delivery(body, headers), now=NOW)


def test_code_scanning_delivery_hints_reconcile_code_scanning_alerts() -> None:
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    delivery = _delivery(body, {"x-github-event": "code_scanning_alert", "x-github-delivery": "delivery-ghes-4"})

    hints = hints_for_delivery("code_scanning_alert", delivery)

    assert [hint.stream for hint in hints] == ["code_scanning_alerts"]
    assert all(hint.reconcile == "incremental" for hint in hints)
