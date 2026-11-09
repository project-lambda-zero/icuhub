"""Connector-level tests for the github.com connector.

Covers auth wiring and rejection of unsupported App configuration, health checks, the
``code_scanning_alerts`` stream with ``Link``-header pagination and the permission-denied
path, the OCSF 2002 mapper, the ``update_code_scanning_alert`` action (plan, apply,
reconcile), and the HMAC webhook verifier and ``code_scanning_alert`` delivery parser.
Requests are answered by ``RouteTransport`` from the synthetic fixtures in
``tests/fixtures/github/``, which follow the documented GitHub REST shapes.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import httpx2
import pytest

from icuhub.connectors._github.models import GitHubConfig, UpdateCodeScanningAlertArgs
from icuhub.kit.auth import BearerToken
from icuhub.kit.errors import AuthFailed, ConfigError, PermissionDenied, WebhookRejected
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import Target, WebhookDelivery
from icuhub_schemas.ocsf import VulnerabilityFinding

github_module = pytest.importorskip(
    "icuhub.connectors.github", reason="github connector implementation is still in progress"
)
GitHub = github_module.GitHub

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "github"
BASE = "https://api.github.test"
PAT_REF = "github-pat"
SECRETS = {PAT_REF: b"synthetic-pat"}
HMAC_SECRET = b"synthetic-webhook-secret"
CONNECTION_ID = "test-connection"
REPO_PATH = "/repos/example-org/example-repo"
ALERTS_PATH = f"{REPO_PATH}/code-scanning/alerts"
ALERT_PATH = f"{ALERTS_PATH}/4"
TARGET = Target(
    id="1001",
    source_uid="github:repository:1001",
    kind="repository",
    display_name="example-org/example-repo",
    attributes={"owner": "example-org", "repo": "example-repo"},
)


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _config(**extra: Any) -> dict[str, Any]:
    return {"base_url": BASE, "personal_access_token": {"ref": PAT_REF}, **extra}


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> GitHub:
    return cast(GitHub, make_connector(GitHub, _config(**config_extra), RouteTransport(routes), SECRETS))


def _recording(payload: Any, log: list[httpx2.Request], status: int = 200) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(request: httpx2.Request) -> dict[str, Any]:
        log.append(request)
        return {"status": status, "json": payload}

    return handler


def _delivery(body: bytes, headers: dict[str, str]) -> WebhookDelivery:
    from datetime import UTC, datetime  # noqa: PLC0415

    return WebhookDelivery(headers=headers, body=body, received_at=datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC))


def _signature(body: bytes, secret: bytes = HMAC_SECRET) -> dict[str, str]:
    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return {"x-hub-signature-256": f"sha256={digest}"}


# --- auth and configuration -------------------------------------------------


def test_bearer_token_is_built_from_resolved_pat() -> None:
    connector = _connector({})

    auth = asyncio.run(connector.build_auth())

    assert isinstance(auth, BearerToken)


def test_non_ascii_pat_is_rejected() -> None:
    connector = cast(
        GitHub,
        make_connector(GitHub, _config(), RouteTransport({}), {PAT_REF: b"\xff\xfe"}),
    )

    with pytest.raises(ConfigError):
        asyncio.run(connector.build_auth())


def test_github_app_configuration_is_rejected_until_app_auth_is_implemented() -> None:
    connector = cast(
        GitHub,
        make_connector(
            GitHub,
            {
                "base_url": BASE,
                "app_id": "12345",
                "app_private_key": {"ref": "github-app-key"},
                "installation_id": "67890",
            },
            RouteTransport({}),
            {"github-app-key": b"synthetic-key"},
        ),
    )

    with pytest.raises(ConfigError):
        asyncio.run(connector.build_auth())


def test_config_requires_exactly_one_auth_mode() -> None:
    with pytest.raises(ValueError):
        GitHubConfig(base_url=BASE)
    with pytest.raises(ValueError):
        GitHubConfig(
            base_url=BASE,
            personal_access_token={"ref": PAT_REF},
            app_id="1",
            app_private_key={"ref": "k"},
            installation_id="2",
        )


# --- health -----------------------------------------------------------------


def test_health_is_healthy_when_rate_limit_probe_succeeds() -> None:
    connector = _connector({("GET", "/rate_limit"): {"status": 200, "json": _load("rate_limit.json")}})

    report = asyncio.run(connector.check())

    assert report.status == "healthy"


def test_health_is_failing_when_vendor_rejects_credentials() -> None:
    connector = _connector({("GET", "/rate_limit"): {"status": 401, "json": {"message": "Bad credentials"}}})

    report = asyncio.run(connector.check())

    assert report.status == "failing"


def test_health_is_degraded_when_permission_is_denied() -> None:
    connector = _connector({("GET", "/rate_limit"): {"status": 403, "json": {"message": "forbidden"}}})

    report = asyncio.run(connector.check())

    assert report.status == "degraded"


# --- code_scanning_alerts stream --------------------------------------------


def _paged_alerts(requests: list[httpx2.Request]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(request: httpx2.Request) -> dict[str, Any]:
        requests.append(request)
        if request.url.params.get("page") == "2":
            return {"status": 200, "json": _load("alerts_page2.json")}
        next_url = f"{BASE}{ALERTS_PATH}?sort=updated&direction=asc&per_page=100&page=2"
        return {
            "status": 200,
            "json": _load("alerts_page1.json"),
            "headers": {"link": f'<{next_url}>; rel="next"'},
        }

    return handler


def test_full_stream_follows_link_header_pages_in_order() -> None:
    requests: list[httpx2.Request] = []
    connector = _connector({("GET", ALERTS_PATH): _paged_alerts(requests)})

    batches = collect_stream(connector, "code_scanning_alerts", target=TARGET, mode="full")

    numbers = [record["number"] for batch in batches for record in batch.records]
    assert numbers == [4, 5, 9]
    assert batches[-1].complete is True
    assert batches[-1].records == []
    first = requests[0]
    assert first.url.params.get("sort") == "updated"
    assert first.url.params.get("direction") == "asc"
    assert first.url.params.get("per_page") == "100"
    assert requests[1].url.params.get("page") == "2"


def test_stream_raises_permission_denied_when_code_scanning_is_forbidden() -> None:
    connector = _connector({("GET", ALERTS_PATH): {"status": 403, "json": {"message": "Resource not accessible"}}})

    with pytest.raises(PermissionDenied):
        collect_stream(connector, "code_scanning_alerts", target=TARGET, mode="full")


def test_stream_raises_auth_failed_on_rejected_credentials() -> None:
    connector = _connector({("GET", ALERTS_PATH): {"status": 401, "json": {"message": "Bad credentials"}}})

    with pytest.raises(AuthFailed):
        collect_stream(connector, "code_scanning_alerts", target=TARGET, mode="full")


# --- mapper: OCSF 2002 ------------------------------------------------------


def test_open_alert_maps_to_new_vulnerability_finding() -> None:
    connector = _connector({})
    raw = _load("alert_open.json")
    raw["_repository_id"] = 1001

    (finding,) = map_all(connector, "code_scanning_alerts", [raw], target=TARGET)

    assert isinstance(finding, VulnerabilityFinding)
    assert finding.class_uid == 2002
    assert finding.activity_id == 1
    assert finding.type_uid == 200201
    assert finding.status_id == 1
    assert finding.severity_id == 4
    assert finding.finding_info.uid == f"{CONNECTION_ID}:repository:1001:alert:4"


def test_dismissed_alert_maps_to_suppressed_status() -> None:
    connector = _connector({})
    raw = _load("alert_dismissed.json")
    raw["_repository_id"] = 1001

    (finding,) = map_all(connector, "code_scanning_alerts", [raw], target=TARGET)

    assert finding.status_id == 3


def test_fixed_alert_maps_to_resolved_status() -> None:
    connector = _connector({})
    raw = _load("webhook_code_scanning_alert.json")["alert"]
    raw["_repository_id"] = 1001

    (finding,) = map_all(connector, "code_scanning_alerts", [raw], target=TARGET)

    assert finding.status_id == 4


def test_alert_without_security_severity_falls_back_to_rule_severity() -> None:
    connector = _connector({})
    raw = _load("alert_dismissed.json")
    raw["_repository_id"] = 1001
    raw["rule"]["severity"] = "warning"
    raw["rule"]["security_severity_level"] = None

    (finding,) = map_all(connector, "code_scanning_alerts", [raw], target=TARGET)

    assert finding.severity_id == 3


# --- action: update_code_scanning_alert -------------------------------------


def test_dismissing_without_reason_is_rejected_by_the_input_model() -> None:
    with pytest.raises(ValueError):
        UpdateCodeScanningAlertArgs(owner="example-org", repo="example-repo", alert_number=4, state="dismissed")


def test_plan_dismiss_of_open_alert_is_a_change() -> None:
    connector = _connector({("GET", ALERT_PATH): {"status": 200, "json": _load("alert_open.json")}})
    spec = GitHub.actions()["update_code_scanning_alert"]
    args = UpdateCodeScanningAlertArgs(
        owner="example-org",
        repo="example-repo",
        alert_number=4,
        state="dismissed",
        dismissed_reason="false positive",
        dismissed_comment="Input is validated upstream",
    )

    plan = asyncio.run(spec.plan(connector, args))

    assert plan.changed is True
    assert plan.request["method"] == "PATCH"
    assert plan.request["path"] == ALERT_PATH
    assert plan.request["json"] == {
        "state": "dismissed",
        "dismissed_reason": "false positive",
        "dismissed_comment": "Input is validated upstream",
    }
    assert len(plan.idempotency_key) == 64


def test_plan_dismiss_of_already_dismissed_alert_is_a_no_op() -> None:
    connector = _connector({("GET", ALERT_PATH): {"status": 200, "json": _load("alert_dismissed.json")}})
    spec = GitHub.actions()["update_code_scanning_alert"]
    args = UpdateCodeScanningAlertArgs(
        owner="example-org",
        repo="example-repo",
        alert_number=4,
        state="dismissed",
        dismissed_reason="false positive",
    )

    plan = asyncio.run(spec.plan(connector, args))

    assert plan.changed is False


def test_apply_patches_alert_and_reports_succeeded() -> None:
    patched: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ALERT_PATH): {"status": 200, "json": _load("alert_open.json")},
            ("PATCH", ALERT_PATH): _recording(_load("alert_dismissed.json"), patched),
        }
    )
    spec = GitHub.actions()["update_code_scanning_alert"]
    args = UpdateCodeScanningAlertArgs(
        owner="example-org",
        repo="example-repo",
        alert_number=4,
        state="dismissed",
        dismissed_reason="false positive",
        dismissed_comment="Input is validated upstream",
    )
    plan = asyncio.run(spec.plan(connector, args))

    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert len(patched) == 1
    assert json.loads(patched[0].content) == plan.request["json"]


def test_reconcile_reports_succeeded_when_alert_is_dismissed() -> None:
    connector = _connector({("GET", ALERT_PATH): {"status": 200, "json": _load("alert_dismissed.json")}})
    spec = GitHub.actions()["update_code_scanning_alert"]
    args = UpdateCodeScanningAlertArgs(
        owner="example-org",
        repo="example-repo",
        alert_number=4,
        state="dismissed",
        dismissed_reason="false positive",
    )
    plan = asyncio.run(spec.plan(connector, args))
    assert spec.reconcile is not None

    outcome = asyncio.run(spec.reconcile(connector, plan))

    assert outcome.status == "succeeded"


def test_reconcile_reports_failed_when_alert_is_still_open() -> None:
    open_connector = _connector({("GET", ALERT_PATH): {"status": 200, "json": _load("alert_open.json")}})
    dismissed_connector = _connector({("GET", ALERT_PATH): {"status": 200, "json": _load("alert_dismissed.json")}})
    spec = GitHub.actions()["update_code_scanning_alert"]
    args = UpdateCodeScanningAlertArgs(
        owner="example-org",
        repo="example-repo",
        alert_number=4,
        state="dismissed",
        dismissed_reason="false positive",
    )
    plan = asyncio.run(spec.plan(dismissed_connector, args))
    assert spec.reconcile is not None

    outcome = asyncio.run(spec.reconcile(open_connector, plan))

    assert outcome.status == "failed"


# --- webhooks ---------------------------------------------------------------


def test_signed_code_scanning_delivery_verifies() -> None:
    connector = _connector({})
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None

    result = verifier.verify(_delivery(body, {**_signature(body), "x-github-event": "code_scanning_alert",
                                              "x-github-delivery": "delivery-1"}), now=None)

    assert result is not None


def test_delivery_with_wrong_signature_is_rejected() -> None:
    connector = _connector({})
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None

    with pytest.raises(WebhookRejected):
        verifier.verify(_delivery(body, _signature(body, secret=b"other-secret")), now=None)


def test_webhook_secret_must_not_be_empty() -> None:
    connector = _connector({})

    with pytest.raises(ConfigError):
        connector.webhook_verifier(b"")


def test_code_scanning_alert_delivery_parses_to_stream_record() -> None:
    connector = _connector({})
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    delivery = _delivery(
        body,
        {"x-github-event": "code_scanning_alert", "x-github-delivery": "delivery-1"},
    )

    records = connector.receive_event(delivery)

    (record,) = records
    assert record.stream == "code_scanning_alerts"
    assert record.raw["number"] == 4
    assert record.raw["state"] == "fixed"
    assert record.event == "upsert"


def test_unrelated_github_event_produces_no_records() -> None:
    connector = _connector({})
    delivery = _delivery(b"{}", {"x-github-event": "push", "x-github-delivery": "delivery-2"})

    assert connector.receive_event(delivery) == []
