"""Connector-level tests for the github.com connector.

Covers auth wiring for personal access tokens and GitHub App installation tokens, health
checks, the ``code_scanning_alerts`` stream with ``Link``-header pagination and the
permission-denied path, the OCSF 2002 mapper, the ``update_code_scanning_alert`` action
(plan, apply, reconcile), and the HMAC webhook verifier (per-secret verifiers for rotation,
legacy SHA-1 rejection, verified delivery metadata) and ``code_scanning_alert`` delivery parser.
Requests are answered by ``RouteTransport`` from the synthetic fixtures in
``tests/fixtures/github/``, which follow the documented GitHub REST shapes.
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icuhub.connectors._github.actions import apply_merge_pull_request
from icuhub.connectors._github.models import (
    CheckRunArgs,
    CreateCommitStatusArgs,
    CreatePrCommentArgs,
    CreatePullRequestArgs,
    CreateReviewArgs,
    GitHubConfig,
    MergePullRequestArgs,
    UpdateCodeScanningAlertArgs,
)
from icuhub.connectors._github.webhooks import hints_for_delivery
from icuhub.connectors.github import GitHub
from icuhub.kit.auth import BearerToken, GitHubAppAuth
from icuhub.kit.errors import AuthFailed, ConfigError, PermissionDenied, StalePlan, VendorContractError, WebhookRejected
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import ActionOutcome, ActionPlan, Target, WebhookDelivery
from icuhub_schemas.ocsf import VulnerabilityFinding

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "github"
BASE = "https://api.github.com"
PAT_REF = "github-pat"
SECRETS = {PAT_REF: b"synthetic-pat"}
HMAC_SECRET = b"synthetic-webhook-secret"
NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
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
    return WebhookDelivery(headers=headers, body=body, received_at=NOW)


def _signature(body: bytes, secret: bytes = HMAC_SECRET) -> dict[str, str]:
    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return {"x-hub-signature-256": f"sha256={digest}"}


# --- auth and configuration -------------------------------------------------


def test_bearer_token_is_built_from_resolved_pat() -> None:
    connector = _connector({})

    auth = asyncio.run(connector.build_auth())

    assert isinstance(auth, BearerToken)


def test_non_ascii_pat_is_rejected() -> None:
    with pytest.raises(ConfigError, match="must be ASCII"):
        make_connector(GitHub, _config(), RouteTransport({}), {PAT_REF: b"\xff\xfe"})


def test_github_app_configuration_builds_installation_token_auth() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
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
            {"github-app-key": pem},
        ),
    )

    auth = asyncio.run(connector.build_auth())

    assert isinstance(auth, GitHubAppAuth)
    assert auth.app_id == "12345"
    assert auth.installation_id == "67890"
    assert auth.api_base == BASE


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
    current = {"alert": _load("alert_open.json")}

    def read_alert(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": current["alert"]}

    def patch_alert(request: httpx2.Request) -> dict[str, Any]:
        patched.append(request)
        current["alert"] = _load("alert_dismissed.json")
        return {"status": 200, "json": current["alert"]}

    connector = _connector(
        {("GET", ALERT_PATH): read_alert, ("PATCH", ALERT_PATH): patch_alert},
        write_enabled=True,
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


def test_apply_alert_update_is_refused_when_writes_are_disabled() -> None:
    connector = _connector({("GET", ALERT_PATH): {"status": 200, "json": _load("alert_open.json")}})
    spec = GitHub.actions()["update_code_scanning_alert"]
    args = UpdateCodeScanningAlertArgs(
        owner="example-org",
        repo="example-repo",
        alert_number=4,
        state="dismissed",
        dismissed_reason="false positive",
    )
    plan = asyncio.run(spec.plan(connector, args))
    with pytest.raises(ConfigError):
        asyncio.run(spec.apply(connector, plan))


def test_merge_is_refused_without_destructive_enabled() -> None:
    connector = _connector({}, write_enabled=True)
    plan = ActionPlan(
        action="merge_pull_request",
        target_ref="github:example-org/example-repo:pull:1",
        diff={},
        preconditions={},
        idempotency_key="0" * 64,
        changed=True,
        request={},
    )
    with pytest.raises(ConfigError):
        asyncio.run(apply_merge_pull_request(connector, plan))


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

    prior = ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error="timeout")

    outcome = asyncio.run(spec.reconcile(connector, plan, prior))

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

    prior = ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error="timeout")

    outcome = asyncio.run(spec.reconcile(open_connector, plan, prior))

    assert outcome.status == "failed"


# --- webhooks ---------------------------------------------------------------


def test_signed_code_scanning_delivery_verifies() -> None:
    connector = _connector({})
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None

    headers = {
        **_signature(body),
        "x-github-event": "code_scanning_alert",
        "x-github-delivery": "delivery-1",
    }

    result = verifier.verify(_delivery(body, headers), now=NOW)

    assert result is not None


def test_delivery_with_wrong_signature_is_rejected() -> None:
    connector = _connector({})
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None

    with pytest.raises(WebhookRejected):
        verifier.verify(_delivery(body, _signature(body, secret=b"other-secret")), now=NOW)


def test_verified_delivery_carries_github_delivery_id_and_event() -> None:
    connector = _connector({})
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None
    headers = {
        **_signature(body),
        "x-github-event": "code_scanning_alert",
        "x-github-delivery": "delivery-1",
    }

    verified = verifier.verify(_delivery(body, headers), now=NOW)

    assert verified.delivery_id == "delivery-1"
    assert verified.event_type == "code_scanning_alert"


def test_each_rotation_secret_gets_its_own_verifier() -> None:
    connector = _connector({})
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    previous = connector.webhook_verifier(b"previous-secret")
    current = connector.webhook_verifier(HMAC_SECRET)
    assert previous is not None
    assert current is not None
    headers = {
        **_signature(body, secret=b"previous-secret"),
        "x-github-event": "code_scanning_alert",
        "x-github-delivery": "delivery-3",
    }
    delivery = _delivery(body, headers)

    assert previous.verify(delivery, now=NOW).delivery_id == "delivery-3"
    with pytest.raises(WebhookRejected):
        current.verify(delivery, now=NOW)


def test_legacy_sha1_signature_is_rejected() -> None:
    connector = _connector({})
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None
    digest = hmac.new(HMAC_SECRET, body, hashlib.sha1).hexdigest()
    headers = {
        "x-hub-signature": f"sha1={digest}",
        "x-github-event": "code_scanning_alert",
        "x-github-delivery": "delivery-4",
    }

    with pytest.raises(WebhookRejected, match="missing webhook header: x-hub-signature-256"):
        verifier.verify(_delivery(body, headers), now=NOW)


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
    assert record.raw == {
        "event": "code_scanning_alert",
        "delivery_id": "delivery-1",
        "repository_id": 1001,
    }
    assert record.reconcile == "incremental"
    assert record.event == "upsert"


def test_unrelated_github_event_produces_no_records() -> None:
    connector = _connector({})
    delivery = _delivery(b"{}", {"x-github-event": "ping", "x-github-delivery": "delivery-2"})

    assert connector.receive_event(delivery) == []


def test_delivery_without_github_delivery_id_is_rejected() -> None:
    body = (FIXTURES / "webhook_code_scanning_alert.json").read_bytes()
    delivery = _delivery(body, {"x-github-event": "code_scanning_alert"})

    with pytest.raises(VendorContractError, match="lacks X-GitHub-Delivery"):
        hints_for_delivery("code_scanning_alert", delivery)


def test_non_json_delivery_body_is_rejected() -> None:
    delivery = _delivery(
        b"not json",
        {"x-github-event": "code_scanning_alert", "x-github-delivery": "delivery-5"},
    )

    with pytest.raises(VendorContractError, match="must be JSON"):
        hints_for_delivery("code_scanning_alert", delivery)


# --- write actions: gates, reconcile, no-op planning, merge ----------------

HEAD_SHA = "a1b2c3d4" * 5
MERGE_SHA = "c3d4e5f6" * 5
PULL_PATH = f"{REPO_PATH}/pulls/7"
COMMENT_MARKER = "<!-- icuhub-action-key:icuhub:pr-comment-1 -->"


def _pull(*, state: str = "open", merged: bool = False, head: str = HEAD_SHA, **extra: Any) -> dict[str, Any]:
    return {"number": 7, "state": state, "merged": merged, "head": {"sha": head}, **extra}


def _action(name: str) -> Any:
    return GitHub.actions()[name]


def _manual_plan(action: str, request: dict[str, Any] | None = None) -> ActionPlan:
    return ActionPlan(
        action=action,
        target_ref="github:test",
        diff={"manual": True},
        preconditions={"owner": "example-org", "repo": "example-repo"},
        idempotency_key="icuhub-test-key",
        changed=True,
        request=request or {"method": "POST", "path": f"{REPO_PATH}/test", "json": {}},
    )


def test_sarif_upload_is_refused_when_writes_are_disabled() -> None:
    connector = _connector({})
    plan = _manual_plan("upload_code_scanning_sarif")

    with pytest.raises(ConfigError):
        asyncio.run(_action("upload_code_scanning_sarif").apply(connector, plan))


def test_commit_status_is_refused_when_writes_are_disabled() -> None:
    connector = _connector({})
    plan = _manual_plan("create_commit_status")

    with pytest.raises(ConfigError):
        asyncio.run(_action("create_commit_status").apply(connector, plan))


def test_sarif_reconcile_reports_accepted_async_while_processing() -> None:
    routes = {
        ("GET", f"{REPO_PATH}/code-scanning/sarifs/abc123"): {"status": 200, "json": {"processing_status": "pending"}},
    }
    connector = _connector(routes)
    plan = _manual_plan(
        "upload_code_scanning_sarif",
        {"sarif_id": "abc123", "analysis_id": None, "processing_status": "pending"},
    )
    plan.preconditions = {"owner": "example-org", "repo": "example-repo", "head_sha": HEAD_SHA, "ref": "refs/heads/main"}
    prior = ActionOutcome(status="accepted_async", vendor_ref="abc123")

    outcome = asyncio.run(_action("upload_code_scanning_sarif").reconcile(connector, plan, prior))

    assert outcome.status == "accepted_async"
    assert outcome.vendor_ref == "abc123"


def test_pr_comment_plan_is_no_op_when_marked_comment_exists() -> None:
    routes = {
        ("GET", f"{REPO_PATH}/issues/7/comments"): {
            "status": 200,
            "json": [{"id": 11, "body": f"earlier text\n\n{COMMENT_MARKER}", "url": "https://api.github.com/c/11"}],
        },
    }
    connector = _connector(routes)
    args = CreatePrCommentArgs(
        owner="example-org",
        repo="example-repo",
        pull_number=7,
        body="earlier text",
        action_key="icuhub:pr-comment-1",
    )

    plan = asyncio.run(_action("create_pr_comment").plan(connector, args))

    assert plan.changed is False
    assert plan.request["comment_id"] == 11


def test_pr_comment_apply_posts_and_reads_back_marked_comment() -> None:
    body = f"hello\n\n{COMMENT_MARKER}"
    routes = {
        ("GET", f"{REPO_PATH}/issues/7/comments"): {"status": 200, "json": []},
        ("POST", f"{REPO_PATH}/issues/7/comments"): {"status": 201, "json": {"id": 12, "body": body}},
        ("GET", f"{REPO_PATH}/issues/comments/12"): {"status": 200, "json": {"id": 12, "body": body}},
    }
    connector = _connector(routes, write_enabled=True)
    args = CreatePrCommentArgs(
        owner="example-org",
        repo="example-repo",
        pull_number=7,
        body="hello",
        action_key="icuhub:pr-comment-1",
    )

    plan = asyncio.run(_action("create_pr_comment").plan(connector, args))
    outcome = asyncio.run(_action("create_pr_comment").apply(connector, plan))

    assert plan.changed is True
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "12"


def test_review_plan_is_no_op_when_review_exists_at_head() -> None:
    routes = {
        ("GET", PULL_PATH): {"status": 200, "json": _pull()},
        ("GET", f"{PULL_PATH}/reviews"): {
            "status": 200,
            "json": [{"id": 31, "commit_id": HEAD_SHA, "state": "APPROVED"}],
        },
    }
    connector = _connector(routes)
    args = CreateReviewArgs(owner="example-org", repo="example-repo", pull_number=7, event="APPROVE")

    plan = asyncio.run(_action("create_review").plan(connector, args))

    assert plan.changed is False
    assert plan.request["review_id"] == 31


def test_pull_request_plan_is_no_op_when_open_pull_matches() -> None:
    repo = {"name": "example-repo", "owner": {"login": "example-org"}}
    pull = {
        "number": 3,
        "state": "open",
        "head": {"ref": "feature-branch", "repo": repo},
        "base": {"ref": "main", "repo": repo},
    }
    routes = {("GET", f"{REPO_PATH}/pulls"): {"status": 200, "json": [pull]}}
    connector = _connector(routes)
    args = CreatePullRequestArgs(
        owner="example-org",
        repo="example-repo",
        title="Feature",
        head="feature-branch",
        base="main",
    )

    plan = asyncio.run(_action("create_pull_request").plan(connector, args))

    assert plan.changed is False
    assert plan.request["pull_number"] == 3


def test_commit_status_plan_is_no_op_when_latest_status_converged() -> None:
    statuses = [
        {
            "id": 1,
            "context": "icuhub/ci",
            "state": "success",
            "description": "ok",
            "target_url": "https://ci.example.test/1",
            "created_at": "2026-11-09T12:00:00Z",
        }
    ]
    routes = {("GET", f"{REPO_PATH}/commits/{HEAD_SHA}/statuses"): {"status": 200, "json": statuses}}
    connector = _connector(routes)
    args = CreateCommitStatusArgs(
        owner="example-org",
        repo="example-repo",
        sha=HEAD_SHA,
        state="success",
        context="icuhub/ci",
        description="ok",
        target_url="https://ci.example.test/1",
    )

    plan = asyncio.run(_action("create_commit_status").plan(connector, args))

    assert plan.changed is False


def test_check_run_plan_is_refused_with_personal_access_token() -> None:
    connector = _connector({})
    args = CheckRunArgs(
        owner="example-org",
        repo="example-repo",
        sha=HEAD_SHA,
        name="icuhub",
        action_key="icuhub:check-1",
        analysis_id=5,
        status="completed",
        conclusion="success",
        title="Scan",
        summary="Done",
    )

    with pytest.raises(ConfigError):
        asyncio.run(_action("create_or_update_check_run").plan(connector, args))


def test_merge_plan_raises_stale_plan_when_head_differs_from_expected() -> None:
    routes = {("GET", PULL_PATH): {"status": 200, "json": _pull(head=HEAD_SHA)}}
    connector = _connector(routes)
    args = MergePullRequestArgs(
        owner="example-org",
        repo="example-repo",
        pull_number=7,
        expected_head_sha="b" * 40,
    )

    with pytest.raises(StalePlan):
        asyncio.run(_action("merge_pull_request").plan(connector, args))


def test_merge_plan_targets_merge_endpoint_when_head_matches() -> None:
    routes = {("GET", PULL_PATH): {"status": 200, "json": _pull(head=HEAD_SHA)}}
    connector = _connector(routes)
    args = MergePullRequestArgs(
        owner="example-org",
        repo="example-repo",
        pull_number=7,
        expected_head_sha=HEAD_SHA,
    )

    plan = asyncio.run(_action("merge_pull_request").plan(connector, args))

    assert plan.changed is True
    assert plan.request["method"] == "PUT"
    assert plan.request["path"] == f"{PULL_PATH}/merge"


def test_merge_apply_merges_at_planned_head_when_destructive_enabled() -> None:
    open_pull = _pull(head=HEAD_SHA)
    merged_pull = _pull(state="closed", merged=True, head=HEAD_SHA, merge_commit_sha=MERGE_SHA)
    pulls = iter([open_pull, open_pull, merged_pull])
    routes: dict[tuple[str, str], Any] = {
        ("GET", PULL_PATH): lambda _request: {"status": 200, "json": next(pulls)},
        ("PUT", f"{PULL_PATH}/merge"): {"status": 200, "json": {"merged": True, "sha": MERGE_SHA}},
    }
    connector = _connector(routes, write_enabled=True, destructive_enabled=True)
    args = MergePullRequestArgs(
        owner="example-org",
        repo="example-repo",
        pull_number=7,
        expected_head_sha=HEAD_SHA,
    )

    plan = asyncio.run(_action("merge_pull_request").plan(connector, args))
    outcome = asyncio.run(_action("merge_pull_request").apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == MERGE_SHA


@pytest.mark.parametrize(
    ("event", "streams"),
    [
        ("push", ["branches", "commits"]),
        ("workflow_run", ["workflow_runs"]),
        ("workflow_job", ["workflow_jobs"]),
    ],
)
def test_repository_scoped_events_produce_incremental_hints(event: str, streams: list[str]) -> None:
    delivery = _delivery(
        b'{"repository": {"id": 99}}',
        {"x-github-event": event, "x-github-delivery": f"delivery-{event}"},
    )

    hints = hints_for_delivery(event, delivery)

    assert [hint.stream for hint in hints] == streams
    assert all(hint.reconcile == "incremental" for hint in hints)
