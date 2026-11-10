"""Live Fortify SSC acceptance: discovery, complete reads, offline replay, and gated writes.

Requires ICUHUB_ACC=1 and ICUHUB_ACC_FORTIFY_SSC pointing to JSON:
{"config": {"base_url": "https://host/ssc", "api_token": {"ref": "token"},
            "write_enabled": false, "destructive_enabled": false},
 "secrets": {"token": "AutomationToken"},
 "params": {"project_version_id": 42, "issue_id": 1001, "artifact_id": 501,
            "webhook_id": 77, "delivery_id": 900, "delta_export_id": 8,
            "fpr_path": "acceptance/fixture.fpr", "report_path": "acceptance/scan.xml"},
 "allow_writes": false}

Write runs additionally use custom_tag_guid, new_custom_tag_index, assignee, comment, and
webhook_url. Destructive runs use approval_ref and explicitly enable destructive_enabled.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
from pathlib import Path
from typing import Any

import httpx2

from icuhub.connectors.fortify_ssc import FortifySsc
from icuhub.connectors.fortify_ssc.connector import DeltaExportArgs, WebhookDeliveryArgs
from icuhub.connectors.fortify_ssc.models import (
    AddIssueCommentArgs,
    ArtifactArgs,
    AssignIssueArgs,
    AuditIssueArgs,
    CreateWebhookArgs,
    IssueAuditArgs,
    IssueCommentArgs,
    IssueDetailArgs,
    IssueListArgs,
    ProbeArgs,
    ProjectVersionListArgs,
    PurgeArtifactArgs,
    PurgeProjectVersionArgs,
    SetIssueSuppressionArgs,
    UploadFprArgs,
    WebhookHistoryArgs,
    WebhookListArgs,
)
from icuhub.kit.testing import make_connector, map_all
from icuhub.kit.types import ImportedFile

ACCEPTANCE_KIND = "fortify_ssc"


def _connector(acceptance) -> FortifySsc:
    return make_connector(FortifySsc, acceptance.config, httpx2.AsyncHTTPTransport(), acceptance.secrets)  # type: ignore[return-value]


def _run(connector: FortifySsc, name: str, args: Any) -> tuple[Any, Any]:
    spec = connector.actions()[name]
    plan = asyncio.run(spec.plan(connector, args))
    outcome = asyncio.run(spec.apply(connector, plan))
    return plan, outcome


def test_health_target_and_complete_reads(acceptance) -> None:
    connector = _connector(acceptance)
    report = asyncio.run(connector.check())
    acceptance.record("health", report.status in ("healthy", "degraded"), report.status)
    probe = asyncio.run(connector.probe_target(ProbeArgs()))
    acceptance.record(
        "probe_target",
        bool(probe.target_version and probe.effective_context_root),
        probe.target_version,
        context_root=probe.effective_context_root,
        permissions=len(probe.permissions),
    )
    versions = asyncio.run(connector.list_project_versions(ProjectVersionListArgs()))
    acceptance.record("list_project_versions", True, f"{len(versions.records)} versions")

    project_version_id = int(acceptance.params["project_version_id"])
    issue_id = int(acceptance.params["issue_id"])
    issues = asyncio.run(connector.list_issues(IssueListArgs(project_version_id=project_version_id)))
    acceptance.record("list_issues_all_visibility", True, f"{len(issues.issues)} issues")
    detail = asyncio.run(
        connector.get_issue_details(IssueDetailArgs(project_version_id=project_version_id, issue_id=issue_id))
    )
    acceptance.record("get_issue_details", detail.issue.issue_id == issue_id, f"revision {detail.issue.revision}")
    audit = asyncio.run(
        connector.list_issue_audit(IssueAuditArgs(project_version_id=project_version_id, issue_id=issue_id))
    )
    acceptance.record("list_issue_audit", True, f"{len(audit.audit)} entries")
    comments = asyncio.run(
        connector.list_comments(IssueCommentArgs(project_version_id=project_version_id, issue_id=issue_id))
    )
    acceptance.record("list_comments", True, f"{len(comments.comments)} comments")

    artifact = asyncio.run(connector.get_artifact(ArtifactArgs(artifact_id=int(acceptance.params["artifact_id"]))))
    acceptance.record(
        "get_artifact",
        True,
        artifact.artifact.status,
        indexed=artifact.artifact.indexed,
        version=artifact.artifact.version_number,
    )
    webhooks = asyncio.run(connector.list_webhooks(WebhookListArgs()))
    acceptance.record("list_webhooks", True, f"{len(webhooks.webhooks)} definitions")
    if "webhook_id" in acceptance.params:
        webhook_id = int(acceptance.params["webhook_id"])
        history = asyncio.run(connector.list_webhook_history(WebhookHistoryArgs(webhook_id=webhook_id)))
        acceptance.record("list_webhook_history", True, f"{len(history.deliveries)} deliveries")
        if "delivery_id" in acceptance.params:
            delivery = asyncio.run(
                connector.get_webhook_delivery(
                    WebhookDeliveryArgs(webhook_id=webhook_id, delivery_id=int(acceptance.params["delivery_id"]))
                )
            )
            acceptance.record("get_webhook_delivery", True, delivery.delivery.status)
    if "delta_export_id" in acceptance.params:
        delta = asyncio.run(
            connector.get_delta_export(DeltaExportArgs(export_id=int(acceptance.params["delta_export_id"])))
        )
        acceptance.record("get_delta_export", True, delta.state, detail=delta.detail)


def test_offline_fpr_and_report_replay(acceptance) -> None:
    connector = _connector(acceptance)
    for param, method_name, stream in (
        ("fpr_path", "import_fpr", "fpr_issues"),
        ("report_path", "import_report", "report_issues"),
    ):
        if param not in acceptance.params:
            continue
        path = Path(str(acceptance.params[param]))
        imported = ImportedFile(filename=path.name, media_type=None, data=path.read_bytes())

        async def collect() -> list[dict[str, Any]]:
            return [record async for record in getattr(connector, method_name)(imported)]

        records = asyncio.run(collect())
        findings = map_all(connector, stream, records)
        acceptance.record(param, len(records) == len(findings), f"{len(findings)} findings", sha256=hashlib.sha256(imported.data).hexdigest())


def test_revision_checked_issue_writes(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    project_version_id = int(acceptance.params["project_version_id"])
    issue_id = int(acceptance.params["issue_id"])

    def revision() -> int:
        detail = asyncio.run(
            connector.get_issue_details(IssueDetailArgs(project_version_id=project_version_id, issue_id=issue_id))
        )
        return detail.issue.revision

    audit_args = AuditIssueArgs(
        project_version_id=project_version_id,
        issue_id=issue_id,
        revision=revision(),
        custom_tag_guid=str(acceptance.params["custom_tag_guid"]),
        new_custom_tag_index=int(acceptance.params["new_custom_tag_index"]),
        comment=str(acceptance.params.get("comment", "ICUHUB acceptance audit")),
    )
    _, audit = _run(connector, "audit_issue", audit_args)
    acceptance.record("audit_issue", audit.status in ("succeeded", "no_op"), audit.status)
    assert audit.status in ("succeeded", "no_op")

    suppress_args = SetIssueSuppressionArgs(
        project_version_id=project_version_id,
        issue_id=issue_id,
        revision=revision(),
        suppressed=bool(acceptance.params.get("suppressed", True)),
    )
    _, suppression = _run(connector, "set_issue_suppression", suppress_args)
    acceptance.record("set_issue_suppression", suppression.status in ("succeeded", "no_op"), suppression.status)

    assign_args = AssignIssueArgs(
        project_version_id=project_version_id,
        issue_id=issue_id,
        revision=revision(),
        assignee=str(acceptance.params["assignee"]),
    )
    _, assignment = _run(connector, "assign_issue", assign_args)
    acceptance.record("assign_issue", assignment.status in ("succeeded", "no_op"), assignment.status)

    comment_args = AddIssueCommentArgs(
        project_version_id=project_version_id,
        issue_id=issue_id,
        revision=revision(),
        comment=str(acceptance.params.get("comment", "ICUHUB acceptance comment")),
    )
    _, comment = _run(connector, "add_issue_comment", comment_args)
    acceptance.record("add_issue_comment", comment.status == "succeeded", comment.status)


def test_upload_fpr_and_webhook_writes(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    path = Path(str(acceptance.params["fpr_path"]))
    payload = path.read_bytes()
    upload_args = UploadFprArgs(
        project_version_id=int(acceptance.params["project_version_id"]),
        fpr_sha256=hashlib.sha256(payload).hexdigest(),
        fpr_base64=base64.b64encode(payload).decode("ascii"),
    )
    plan, upload = _run(connector, "upload_fpr", upload_args)
    acceptance.record("upload_fpr", upload.status in ("accepted_async", "succeeded"), upload.status, result=upload.result)
    settled = asyncio.run(connector.actions()["upload_fpr"].reconcile(connector, plan, upload))
    acceptance.record("upload_fpr_reconcile", settled.status in ("accepted_async", "succeeded"), settled.status, result=settled.result)

    webhook_args = CreateWebhookArgs(url=str(acceptance.params["webhook_url"]), object_version=0)
    _, webhook = _run(connector, "create_webhook", webhook_args)
    acceptance.record("create_webhook", webhook.status == "succeeded", webhook.status, result=webhook.result)


def test_gated_destructive_purges(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    approval_ref = str(acceptance.params["approval_ref"])
    artifact_args = PurgeArtifactArgs(
        artifact_id=int(acceptance.params["artifact_id"]),
        version_number=int(acceptance.params["artifact_version_number"]),
        approval_ref=approval_ref,
    )
    _, artifact = _run(connector, "purge_artifact", artifact_args)
    acceptance.record("purge_artifact", artifact.status in ("accepted_async", "succeeded"), artifact.status)

    version_args = PurgeProjectVersionArgs(
        project_version_id=int(acceptance.params["project_version_id"]), approval_ref=approval_ref
    )
    _, version = _run(connector, "purge_project_version", version_args)
    acceptance.record("purge_project_version", version.status in ("accepted_async", "succeeded", "no_op"), version.status)
