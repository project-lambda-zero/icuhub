"""Fortify SSC action behavior against the verified v1 API contracts."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from typing import Any, cast

import pytest

from icuhub.connectors.fortify_ssc import FortifySsc
from icuhub.connectors.fortify_ssc.models import (
    AddIssueCommentArgs,
    AssignIssueArgs,
    AuditIssueArgs,
    CreateWebhookArgs,
    PurgeArtifactArgs,
    PurgeProjectVersionArgs,
    SetIssueSuppressionArgs,
    UploadFprArgs,
)
from icuhub.kit.errors import PermissionDenied, StalePlan
from icuhub.kit.testing import RouteTransport, make_connector
from icuhub.kit.types import ActionPlan

BASE = "https://ssc.example.test/ssc"
API = "/ssc/api/v1"
TOKEN_REF = "fortify-token"
SECRETS = {TOKEN_REF: b"fixture-token"}
ISSUE_PATH = f"{API}/issueDetails/1001"
AUDIT_PATH = f"{API}/projectVersions/42/issues/action/audit"
SUPPRESS_PATH = f"{API}/projectVersions/42/issues/action/suppress"
ASSIGN_PATH = f"{API}/projectVersions/42/issues/action/assignUser"
ARTIFACTS_PATH = f"{API}/projectVersions/42/artifacts"
TAG_GUID = "11111111-1111-1111-1111-111111111111"


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> FortifySsc:
    config = {"base_url": BASE, "api_token": {"ref": TOKEN_REF}, "write_enabled": True, **config_extra}
    return cast(FortifySsc, make_connector(FortifySsc, config, RouteTransport(routes), SECRETS))


def _details(state: dict[str, Any]) -> Any:
    def handler(request: Any) -> dict[str, Any]:
        return {"status": 200, "json": {"data": dict(state)}}

    return handler


def _issue_state(**changes: Any) -> dict[str, Any]:
    return {
        "id": 1001,
        "projectVersionId": 42,
        "revision": 3,
        "customTagValues": [{"customTagGuid": TAG_GUID, "newCustomTagIndex": 0}],
        "suppressed": False,
        "assignedUser": None,
        **changes,
    }


def _success() -> dict[str, Any]:
    return {"status": 200, "json": {"data": {"status": "success"}}}


def _spec(name: str) -> Any:
    return FortifySsc.actions()[name]


def _audit_args() -> AuditIssueArgs:
    return AuditIssueArgs(
        project_version_id=42,
        issue_id=1001,
        revision=3,
        custom_tag_guid=TAG_GUID,
        new_custom_tag_index=1,
        comment=None,
    )


def test_audit_plan_uses_custom_tag_collection_action() -> None:
    connector = _connector({("GET", ISSUE_PATH): _details(_issue_state())})
    plan: ActionPlan = asyncio.run(_spec("audit_issue").plan(connector, _audit_args()))

    assert plan.changed is True
    assert plan.diff == {"customTag": {"guid": TAG_GUID, "from": 0, "to": 1}}
    assert plan.preconditions == {"revision": 3}
    assert plan.request == {
        "method": "POST",
        "path": "/api/v1/projectVersions/42/issues/action/audit",
        "json": {
            "issues": [{"id": 1001, "revision": 3}],
            "customTagAudit": [{"customTagGuid": TAG_GUID, "newCustomTagIndex": 1}],
            "comment": None,
        },
    }


def test_audit_unchanged_tag_is_no_op_without_second_read() -> None:
    seen: list[Any] = []

    def details(request: Any) -> dict[str, Any]:
        seen.append(request)
        return {"status": 200, "json": {"data": _issue_state(customTagValues=[{"customTagGuid": TAG_GUID, "newCustomTagIndex": 1}])}}

    connector = _connector({("GET", ISSUE_PATH): details})
    spec = _spec("audit_issue")
    plan = asyncio.run(spec.plan(connector, _audit_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert outcome.status == "no_op"
    assert len(seen) == 1


def test_audit_apply_validates_and_reconciles_without_repeating_write() -> None:
    state = _issue_state()
    posts: list[dict[str, Any]] = []

    def post(request: Any) -> dict[str, Any]:
        posts.append(json.loads(request.content))
        state["customTagValues"] = [{"customTagGuid": TAG_GUID, "newCustomTagIndex": 1}]
        return _success()

    connector = _connector({("GET", ISSUE_PATH): _details(state), ("POST", AUDIT_PATH): post})
    spec = _spec("audit_issue")
    plan = asyncio.run(spec.plan(connector, _audit_args()))
    outcome = asyncio.run(spec.apply(connector, plan))
    replay = asyncio.run(spec.reconcile(connector, plan, outcome))

    assert outcome.status == "succeeded"
    assert outcome.result == {
        "reconciled": True,
        "customTag": {"customTagGuid": TAG_GUID, "newCustomTagIndex": 1},
    }
    assert replay.status == "succeeded"
    assert len(posts) == 1


def test_audit_vendor_error_is_not_http_success() -> None:
    connector = _connector(
        {
            ("GET", ISSUE_PATH): _details(_issue_state()),
            ("POST", AUDIT_PATH): {"status": 200, "json": {"data": {"status": "error", "message": "revision conflict"}}},
        }
    )
    spec = _spec("audit_issue")
    plan = asyncio.run(spec.plan(connector, _audit_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "failed"
    assert outcome.error == "revision conflict"


def test_apply_refuses_stale_revision_before_write() -> None:
    state = _issue_state()
    connector = _connector({("GET", ISSUE_PATH): _details(state)})
    spec = _spec("audit_issue")
    plan = asyncio.run(spec.plan(connector, _audit_args()))
    state["revision"] = 4

    with pytest.raises(StalePlan, match="moved to revision 4"):
        asyncio.run(spec.apply(connector, plan))


def test_suppression_write_reads_back_and_never_reposts() -> None:
    state = _issue_state()
    posts: list[dict[str, Any]] = []

    def post(request: Any) -> dict[str, Any]:
        posts.append(json.loads(request.content))
        state["suppressed"] = True
        return _success()

    connector = _connector({("GET", ISSUE_PATH): _details(state), ("POST", SUPPRESS_PATH): post})
    spec = _spec("set_issue_suppression")
    args = SetIssueSuppressionArgs(project_version_id=42, issue_id=1001, revision=3, suppressed=True)
    plan = asyncio.run(spec.plan(connector, args))
    outcome = asyncio.run(spec.apply(connector, plan))
    replay = asyncio.run(spec.reconcile(connector, plan, outcome))

    assert posts == [{"issues": [{"id": 1001, "revision": 3}], "suppressed": True}]
    assert outcome.status == "succeeded"
    assert replay.status == "succeeded"
    assert len(posts) == 1


def test_assignment_write_reads_back_official_user_field() -> None:
    state = _issue_state()
    posts: list[dict[str, Any]] = []

    def post(request: Any) -> dict[str, Any]:
        posts.append(json.loads(request.content))
        state["assignedUser"] = {"userName": "analyst", "hasAccess": True}
        return _success()

    connector = _connector({("GET", ISSUE_PATH): _details(state), ("POST", ASSIGN_PATH): post})
    spec = _spec("assign_issue")
    args = AssignIssueArgs(project_version_id=42, issue_id=1001, revision=3, assignee="analyst")
    plan = asyncio.run(spec.plan(connector, args))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert posts == [{"issues": [{"id": 1001, "revision": 3}], "user": "analyst"}]
    assert outcome.status == "succeeded"
    assert outcome.result == {"reconciled": True}


def test_comment_write_uses_audit_action_and_bounded_comment_readback() -> None:
    posts: list[dict[str, Any]] = []
    comment_reads: list[Any] = []

    def post(request: Any) -> dict[str, Any]:
        posts.append(json.loads(request.content))
        return _success()

    def comments(request: Any) -> dict[str, Any]:
        comment_reads.append(request)
        return {
            "status": 200,
            "json": {
                "data": [
                    {
                        "issueId": 1001,
                        "seqNumber": 9,
                        "comment": "triage complete",
                        "userName": "analyst",
                        "auditTime": "2026-03-01T12:00:00Z",
                    }
                ]
            },
        }

    connector = _connector(
        {
            ("GET", ISSUE_PATH): _details(_issue_state()),
            ("POST", AUDIT_PATH): post,
            ("GET", f"{API}/issues/1001/comments"): comments,
        }
    )
    spec = _spec("add_issue_comment")
    args = AddIssueCommentArgs(project_version_id=42, issue_id=1001, revision=3, comment="triage complete")
    plan = asyncio.run(spec.plan(connector, args))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert posts == [{"issues": [{"id": 1001, "revision": 3}], "comment": "triage complete"}]
    assert outcome.status == "succeeded"
    assert len(comment_reads) == 1


def _upload_args(payload: bytes) -> UploadFprArgs:
    return UploadFprArgs(
        project_version_id=42,
        fpr_sha256=hashlib.sha256(payload).hexdigest(),
        fpr_base64=base64.b64encode(payload).decode("ascii"),
    )


def test_upload_fpr_natural_key_dedupes_existing_artifact() -> None:
    payload = b"fpr-offline-fixture"
    args = _upload_args(payload)
    name = f"icuhub-{args.fpr_sha256}.fpr"
    artifact = {
        "id": 501,
        "projectVersionId": 42,
        "fileName": name,
        "fileSize": len(payload),
        "status": "PROCESS_COMPLETE",
        "indexed": True,
    }
    connector = _connector(
        {
            ("GET", ARTIFACTS_PATH): {"status": 200, "json": {"data": [artifact]}},
            ("GET", f"{API}/artifacts/501"): {"status": 200, "json": {"data": artifact}},
        }
    )
    spec = _spec("upload_fpr")
    plan = asyncio.run(spec.plan(connector, args))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.result == {"artifact_id": 501, "indexed": True}


def test_upload_fpr_persists_async_id_and_reconcile_does_not_reupload() -> None:
    payload = b"fpr-offline-fixture"
    args = _upload_args(payload)
    artifact: dict[str, Any] = {
        "id": 501,
        "projectVersionId": 42,
        "fileName": f"icuhub-{args.fpr_sha256}.fpr",
        "fileSize": len(payload),
        "status": "PROCESSING",
        "indexed": False,
    }
    posts: list[Any] = []
    artifact_list_calls = 0

    def empty_artifacts(request: Any) -> dict[str, Any]:
        nonlocal artifact_list_calls
        artifact_list_calls += 1
        return {"status": 200, "json": {"data": []}}

    def upload(request: Any) -> dict[str, Any]:
        posts.append(request)
        return {"status": 201, "json": {"data": dict(artifact)}}

    connector = _connector(
        {
            ("GET", ARTIFACTS_PATH): empty_artifacts,
            ("POST", ARTIFACTS_PATH): upload,
            ("GET", f"{API}/artifacts/501"): lambda request: {"status": 200, "json": {"data": dict(artifact)}},
        }
    )
    spec = _spec("upload_fpr")
    plan = asyncio.run(spec.plan(connector, args))
    accepted = asyncio.run(spec.apply(connector, plan))

    assert accepted.status == "accepted_async"
    assert accepted.result == {"artifact_id": 501, "indexed": False}
    assert len(posts) == 1
    assert artifact_list_calls == 1

    artifact["status"] = "PROCESS_COMPLETE"
    artifact["indexed"] = True
    settled = asyncio.run(spec.reconcile(connector, plan, accepted))
    assert settled.status == "succeeded"
    assert len(posts) == 1
    assert artifact_list_calls == 1


def test_create_webhook_persists_id_and_verifies_definition() -> None:
    posts: list[Any] = []
    hook: dict[str, Any] = {}

    def create(request: Any) -> dict[str, Any]:
        posts.append(request)
        hook.update(json.loads(request.content))
        hook["id"] = 77
        return {"status": 201, "json": {"data": dict(hook)}}

    connector = _connector(
        {
            ("POST", f"{API}/webhooks"): create,
            ("GET", f"{API}/webhooks/77"): lambda request: {"status": 200, "json": {"data": dict(hook)}},
        }
    )
    spec = _spec("create_webhook")
    args = CreateWebhookArgs(url="https://hooks.example.test/ssc", object_version=0)
    plan = asyncio.run(spec.plan(connector, args))
    outcome = asyncio.run(spec.apply(connector, plan))
    replay = asyncio.run(spec.reconcile(connector, plan, outcome))

    assert plan.request["json"]["url"] == args.url
    assert plan.request["json"]["contentType"] == "JSON"
    assert "name" not in plan.request["json"]
    assert outcome.status == "succeeded"
    assert outcome.result == {"reconciled": True, "webhook_id": 77}
    assert replay.status == "succeeded"
    assert len(posts) == 1


def test_write_action_denied_without_write_enabled() -> None:
    connector = _connector({}, write_enabled=False)
    with pytest.raises(PermissionDenied, match="write_enabled"):
        asyncio.run(_spec("audit_issue").plan(connector, _audit_args()))


def test_purge_artifact_denied_without_destructive_flag() -> None:
    connector = _connector({})
    args = PurgeArtifactArgs(artifact_id=501, version_number=1, approval_ref="CHG-1")
    with pytest.raises(PermissionDenied):
        asyncio.run(_spec("purge_artifact").plan(connector, args))


def test_purge_artifact_reconciles_absence_without_second_write() -> None:
    artifact = {"id": 501, "versionNumber": 1, "status": "PROCESS_COMPLETE", "purged": False}
    posts: list[Any] = []

    def purge(request: Any) -> dict[str, Any]:
        posts.append(request)
        artifact["purged"] = True
        artifact["status"] = "PURGED"
        return {"status": 200, "json": {"data": None}}

    connector = _connector(
        {
            ("GET", f"{API}/artifacts/501"): lambda request: {"status": 200, "json": {"data": dict(artifact)}},
            ("POST", f"{API}/artifacts/action/purge"): purge,
        },
        destructive_enabled=True,
    )
    spec = _spec("purge_artifact")
    args = PurgeArtifactArgs(artifact_id=501, version_number=1, approval_ref="CHG-1")
    plan = asyncio.run(spec.plan(connector, args))
    outcome = asyncio.run(spec.apply(connector, plan))
    replay = asyncio.run(spec.reconcile(connector, plan, outcome))

    assert outcome.status == "succeeded"
    assert replay.status == "succeeded"
    assert len(posts) == 1


def test_purge_project_version_denied_without_destructive_flag() -> None:
    connector = _connector({})
    args = PurgeProjectVersionArgs(project_version_id=42, approval_ref="CHG-1")
    with pytest.raises(PermissionDenied):
        asyncio.run(_spec("purge_project_version").plan(connector, args))


def test_purge_project_version_purges_artifacts_without_deleting_version() -> None:
    artifact = {"id": 501, "versionNumber": 1, "status": "PROCESS_COMPLETE", "purged": False}
    posts: list[dict[str, Any]] = []

    def purge(request: Any) -> dict[str, Any]:
        posts.append(json.loads(request.content))
        artifact["purged"] = True
        artifact["status"] = "PURGED"
        return {"status": 200, "json": {"data": None}}

    connector = _connector(
        {
            ("GET", f"{API}/projectVersions/42"): {"status": 200, "json": {"data": {"id": 42, "name": "1.0"}}},
            ("GET", ARTIFACTS_PATH): {"status": 200, "json": {"data": [dict(artifact)]}},
            ("GET", f"{API}/artifacts/501"): lambda request: {"status": 200, "json": {"data": dict(artifact)}},
            ("POST", f"{API}/projectVersions/action/purge"): purge,
        },
        destructive_enabled=True,
    )
    spec = _spec("purge_project_version")
    args = PurgeProjectVersionArgs(project_version_id=42, approval_ref="CHG-1")
    plan = asyncio.run(spec.plan(connector, args))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.request == {
        "method": "POST",
        "path": "/api/v1/projectVersions/action/purge",
        "json": {"projectVersionIds": [42]},
    }
    assert plan.preconditions == {"approval_ref": "CHG-1", "artifact_ids": [501]}
    assert posts == [{"projectVersionIds": [42]}]
    assert outcome.status == "succeeded"
    assert outcome.result == {"artifact_ids": [501], "purged": True}


def test_purge_project_version_with_no_artifacts_is_no_op() -> None:
    connector = _connector(
        {
            ("GET", f"{API}/projectVersions/42"): {"status": 200, "json": {"data": {"id": 42, "name": "1.0"}}},
            ("GET", ARTIFACTS_PATH): {"status": 200, "json": {"data": []}},
        },
        destructive_enabled=True,
    )
    spec = _spec("purge_project_version")
    args = PurgeProjectVersionArgs(project_version_id=42, approval_ref="CHG-1")
    plan = asyncio.run(spec.plan(connector, args))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert outcome.status == "no_op"
