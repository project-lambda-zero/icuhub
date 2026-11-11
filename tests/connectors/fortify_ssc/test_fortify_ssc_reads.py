"""Fortify SSC discovery, bounded reads, delta status, and offline bindings."""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any, cast

import pytest

from icuhub.connectors.fortify_ssc import FortifySsc
from icuhub.connectors.fortify_ssc.connector import DeltaExportArgs, WebhookDeliveryArgs
from icuhub.connectors.fortify_ssc.models import (
    ArtifactArgs,
    IssueAuditArgs,
    IssueCommentArgs,
    IssueDetailArgs,
    IssueListArgs,
    ProbeArgs,
    ProjectVersionListArgs,
    WebhookHistoryArgs,
    WebhookListArgs,
)
from icuhub.kit.errors import VendorContractError
from icuhub.kit.testing import RouteTransport, make_connector, map_all
from icuhub.kit.types import ImportedFile

BASE = "https://ssc.example.test/ssc"
API = "/ssc/api/v1"
TOKEN_REF = "fortify-token"


def _connector(routes: dict[tuple[str, str], Any]) -> FortifySsc:
    return cast(
        FortifySsc,
        make_connector(
            FortifySsc,
            {"base_url": BASE, "api_token": {"ref": TOKEN_REF}},
            RouteTransport(routes),
            {TOKEN_REF: b"fixture-token"},
        ),
    )


def _issue() -> dict[str, Any]:
    return {
        "id": 1001,
        "issueInstanceId": "instance-1",
        "projectVersionId": 42,
        "revision": 3,
        "issueName": "SQL Injection",
        "fullFileName": "src/app/Db.java",
        "lineNumber": 88,
        "foundDate": "2026-03-01T10:00:00Z",
        "hidden": True,
        "removed": True,
        "suppressed": True,
    }


def _webhook() -> dict[str, Any]:
    return {
        "id": 77,
        "objectVersion": 2,
        "contentType": "JSON",
        "url": "https://hooks.example.test/ssc",
        "active": True,
        "monitorApps": "ALL",
        "monitorEvents": "ALL",
    }


def _delivery() -> dict[str, Any]:
    return {
        "id": 900,
        "webHookId": 77,
        "createdAt": "2026-03-01T12:00:00Z",
        "status": "SUCCESS",
        "responseCode": 200,
    }


def test_registered_surface_includes_offline_streams_and_all_reads() -> None:
    connector = _connector({})

    assert set(connector.streams()) == {"issues", "artifacts", "activity", "fpr_issues", "report_issues"}
    assert set(connector.importers()) == {"fortify_fpr", "fortify_report"}
    assert {
        "probe_target",
        "list_project_versions",
        "list_issues",
        "get_issue",
        "get_issue_details",
        "list_issue_audit",
        "list_comments",
        "get_artifact",
        "download_fpr",
        "get_delta_export",
        "list_webhooks",
        "list_webhook_history",
        "get_webhook_delivery",
    } <= set(connector.operations())


def test_probe_target_reads_version_context_capabilities_and_permissions() -> None:
    seen: list[Any] = []

    def session(request: Any) -> dict[str, Any]:
        seen.append(request)
        return {
            "status": 200,
            "json": {
                "data": {
                    "webappVersion": "25.4.0.0137",
                    "applicationContextPath": "/ssc",
                    "licenseCapabilities": [{"key": "sast", "value": "enabled"}],
                    "permissions": ["issue.read", "artifact.read"],
                }
            },
        }

    connector = _connector({("POST", f"{API}/userSession/info"): session})
    output = asyncio.run(connector.probe_target(ProbeArgs()))

    assert output.target_version == "25.4.0.0137"
    assert output.effective_context_root == "/ssc"
    assert output.capabilities[0].key == "sast"
    assert output.permissions == ["issue.read", "artifact.read"]
    assert json.loads(seen[0].content) == ""


def test_list_project_versions_preserves_project_identity() -> None:
    seen: list[Any] = []

    def versions(request: Any) -> dict[str, Any]:
        seen.append(request)
        return {
            "status": 200,
            "json": {"data": [{"id": 42, "name": "1.0", "project": {"name": "payments"}}]},
        }

    connector = _connector({("GET", f"{API}/projectVersions"): versions})
    output = asyncio.run(connector.list_project_versions(ProjectVersionListArgs(include_inactive=True)))

    assert output.records[0].project_version_id == 42
    assert output.records[0].project_name == "payments"
    assert seen[0].url.params["includeInactive"] == "true"


def test_list_issues_includes_every_visibility_state() -> None:
    seen: list[Any] = []

    def issues(request: Any) -> dict[str, Any]:
        seen.append(request)
        return {"status": 200, "json": {"data": [_issue()]}}

    connector = _connector({("GET", f"{API}/projectVersions/42/issues"): issues})
    output = asyncio.run(connector.list_issues(IssueListArgs(project_version_id=42)))

    assert output.issues[0].hidden is True
    assert output.issues[0].removed is True
    assert output.issues[0].suppressed is True
    assert seen[0].url.params["showhidden"] == "true"
    assert seen[0].url.params["showremoved"] == "true"
    assert seen[0].url.params["showsuppressed"] == "true"


def test_issue_detail_rejects_cross_project_response() -> None:
    connector = _connector(
        {("GET", f"{API}/issueDetails/1001"): {"status": 200, "json": {"data": _issue() | {"projectVersionId": 99}}}}
    )

    with pytest.raises(VendorContractError, match="different project version"):
        asyncio.run(connector.get_issue_details(IssueDetailArgs(project_version_id=42, issue_id=1001)))


def test_audit_read_enforces_response_bound() -> None:
    audit = {
        "sequenceNumber": 1,
        "issueId": 1001,
        "auditDateTime": "2026-03-01T12:00:00Z",
        "attributeName": "customTag",
        "oldValue": "0",
        "newValue": "1",
        "userName": "analyst",
        "valueType": "LIST",
        "conflict": False,
    }
    connector = _connector(
        {("GET", f"{API}/issues/1001/auditHistory"): {"status": 200, "json": {"data": [audit, audit | {"sequenceNumber": 2}]}}}
    )

    with pytest.raises(VendorContractError, match="exceeds the configured bound"):
        asyncio.run(connector.list_issue_audit(IssueAuditArgs(project_version_id=42, issue_id=1001, limit=1)))


def test_comment_artifact_and_webhook_history_reads_validate_identity() -> None:
    comment = {
        "seqNumber": 9,
        "issueId": 1001,
        "projectVersionId": 42,
        "comment": "confirmed",
        "auditTime": "2026-03-01T12:00:00Z",
        "userName": "analyst",
    }
    artifact = {
        "id": 501,
        "projectVersionId": 42,
        "status": "PROCESS_COMPLETE",
        "indexed": True,
        "versionNumber": 1,
        "purged": False,
    }
    connector = _connector(
        {
            ("GET", f"{API}/issues/1001/comments"): {"status": 200, "json": {"data": [comment]}},
            ("GET", f"{API}/artifacts/501"): {"status": 200, "json": {"data": artifact}},
            ("GET", f"{API}/webhooks"): {"status": 200, "json": {"data": [_webhook()]}},
            ("GET", f"{API}/webhooks/77/history"): {"status": 200, "json": {"data": [_delivery()]}},
            ("GET", f"{API}/webhooks/77/history/900"): {"status": 200, "json": {"data": _delivery()}},
        }
    )

    comments = asyncio.run(connector.list_comments(IssueCommentArgs(project_version_id=42, issue_id=1001)))
    artifact_output = asyncio.run(connector.get_artifact(ArtifactArgs(artifact_id=501)))
    webhooks = asyncio.run(connector.list_webhooks(WebhookListArgs()))
    history = asyncio.run(connector.list_webhook_history(WebhookHistoryArgs(webhook_id=77)))
    delivery = asyncio.run(connector.get_webhook_delivery(WebhookDeliveryArgs(webhook_id=77, delivery_id=900)))

    assert comments.comments[0].comment == "confirmed"
    assert artifact_output.artifact.indexed is True
    assert webhooks.webhooks[0].webhook_id == 77
    assert history.deliveries[0].delivery_id == 900
    assert delivery.delivery.status == "SUCCESS"


@pytest.mark.parametrize(
    "state",
    ["EXPORT_PROCESS_STARTED", "EXPORT_PROCESS_COMPLETED", "EXPORT_PROCESS_FAILED"],
)
def test_delta_export_status_uses_official_states(state: str) -> None:
    connector = _connector(
        {
            ("GET", f"{API}/issuesDeltaExports/8"): {
                "status": 200,
                "json": {"data": {"id": 8, "status": state, "messages": "fixture"}},
            }
        }
    )

    output = asyncio.run(connector.get_delta_export(DeltaExportArgs(export_id=8)))

    assert output.export_id == 8
    assert output.state == state


def test_download_fpr_uses_single_use_token_and_hashes_bytes() -> None:
    seen: list[Any] = []
    payload = b"bounded-fpr-fixture"

    def download(request: Any) -> dict[str, Any]:
        seen.append(request)
        return {"status": 200, "text": payload.decode("ascii")}

    connector = _connector(
        {
            ("POST", f"{API}/tokens"): {"status": 201, "json": {"data": {"token": "single-use-token"}}},
            ("GET", f"{API}/artifacts/501/download"): download,
        }
    )

    output = asyncio.run(connector.download_fpr(ArtifactArgs(artifact_id=501)))

    assert output.artifact_id == 501
    assert output.sha256 == hashlib.sha256(payload).hexdigest()
    assert seen[0].url.params["mat"] == "single-use-token"


def test_offline_report_import_maps_webinspect_without_network() -> None:
    connector = _connector({})
    imported = ImportedFile(
        filename="scan.xml",
        media_type="application/xml",
        data=b"""<Scan version="1.0"><Issues><Issue><VulnerabilityID>7</VulnerabilityID><URL>https://app.example.test/a</URL><Name>XSS</Name><Severity>3</Severity></Issue></Issues></Scan>""",
    )

    async def collect() -> list[dict[str, Any]]:
        return [record async for record in connector.import_report(imported)]

    records = asyncio.run(collect())
    findings = map_all(connector, "report_issues", records)

    assert len(records) == 1
    assert records[0]["profile"] == "webinspect_scan"
    assert findings[0].class_uid == 2002
    assert findings[0].finding_info.uid_alt == records[0]["native_id"]
    assert findings[0].severity_id == 4


def test_offline_fpr_mapper_binding_preserves_identity_and_suppression() -> None:
    connector = _connector({})
    raw = {
        "file_uuid": "file-uuid",
        "instance_id": "instance-id",
        "artifact_sha256": "a" * 64,
        "issue_name": "SQL Injection",
        "path": "src/app.py",
        "line": 12,
        "suppressed": True,
        "rule": {"accuracy": 5, "impact": 5, "probability": 5},
        "confidence": 5,
    }

    (finding,) = map_all(connector, "fpr_issues", [raw])

    assert finding.class_uid == 2002
    assert finding.finding_info.uid == "fortify_fpr:file-uuid:instance-id"
    assert finding.metadata.uid == "a" * 64
    assert finding.status_id == 3
    assert finding.severity_id == 5
