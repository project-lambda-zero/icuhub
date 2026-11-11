"""Opt-in Fortify on Demand acceptance with live HTTP and separately gated writes."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx2
import pytest

from icuhub.connectors.fortify_fod import FortifyFod
from icuhub.connectors.fortify_fod.models import (
    BulkAuditInput,
    CancelScanInput,
    CreateReportInput,
    DataExportArgs,
    DeleteResourceInput,
    DownloadFprArgs,
    EmptyArgs,
    ImportScanInput,
    IssueArgs,
    IssueHistoryArgs,
    ReleaseArgs,
    ReleaseScanArgs,
    ReportArgs,
    StartScanInput,
)
from icuhub.kit.testing import collect_stream, make_connector, map_all
from icuhub.kit.types import Target

ACCEPTANCE_KIND = "fortify_fod"


def _connector(acceptance) -> FortifyFod:
    config = {
        **acceptance.config,
        "write_enabled": acceptance.allow_writes,
        "destructive_enabled": bool(acceptance.params.get("allow_destructive", False)),
    }
    return make_connector(FortifyFod, config, httpx2.AsyncHTTPTransport(), acceptance.secrets)  # type: ignore[return-value]


def _target(release_id: str) -> Target:
    return Target(
        id=f"release-{release_id}",
        source_uid=release_id,
        kind="release",
        display_name=f"Release {release_id}",
        attributes={},
    )


def _run(connector: FortifyFod, name: str, args: Any) -> tuple[Any, Any]:
    spec = connector.actions()[name]
    plan = asyncio.run(spec.plan(connector, args))
    outcome = asyncio.run(spec.apply(connector, plan))
    if outcome.status in ("accepted_async", "outcome_unknown"):
        assert spec.reconcile is not None
        outcome = asyncio.run(spec.reconcile(connector, plan, outcome))
    return plan, outcome


def _payload(path: str) -> tuple[str, str, int]:
    content = Path(path).read_bytes()
    return base64.b64encode(content).decode("ascii"), hashlib.sha256(content).hexdigest(), len(content)


def test_health_target_and_complete_live_reads(acceptance) -> None:
    connector = _connector(acceptance)
    release_id = str(acceptance.params["release_id"])
    target = _target(release_id)
    report = asyncio.run(connector.check())
    acceptance.record("health", report.status in ("healthy", "degraded"), report.status)
    probe = asyncio.run(connector.probe_target(EmptyArgs()))
    acceptance.record("probe_target", bool(probe.record["tenant"]), "tenant and entitlement probes completed")
    release = asyncio.run(connector.get_release(ReleaseArgs(release_id=release_id)))
    acceptance.record("get_release", str(release.record.get("releaseId")) == release_id, "release read")

    issue_batches = collect_stream(connector, "issues", target=target, mode="full")
    issue_records = [record for batch in issue_batches for record in batch.records]
    findings = map_all(connector, "issues", issue_records)
    acceptance.record(
        "issues_complete_reconciliation",
        bool(issue_batches and issue_batches[-1].complete),
        f"{len(issue_records)} issues",
        mapped_findings=len(findings),
    )
    if issue_records:
        issue_id = str(issue_records[0]["id"])
        detail = asyncio.run(connector.get_issue_details(IssueArgs(release_id=release_id, vuln_id=issue_id)))
        history = asyncio.run(
            connector.get_issue_history(IssueHistoryArgs(release_id=release_id, vuln_id=issue_id))
        )
        acceptance.record("issue_details_and_history", bool(detail.record), f"history keys {sorted(history.record)}")

    scan_batches = collect_stream(connector, "scans", target=target, mode="full")
    scan_records = [record for batch in scan_batches for record in batch.records]
    scans = map_all(connector, "scans", scan_records)
    acceptance.record(
        "scans_complete_reconciliation",
        bool(scan_batches and scan_batches[-1].complete),
        f"{len(scan_records)} scans",
        mapped_records=len(scans),
    )
    if scan_records:
        scan = asyncio.run(
            connector.get_scan(ReleaseScanArgs(release_id=release_id, scan_id=str(scan_records[0]["scanId"])))
        )
        acceptance.record("get_scan", bool(scan.record), str(scan.record.get("analysisStatusType")))
    fpr = asyncio.run(connector.download_fpr(DownloadFprArgs(release_id=release_id, scan_type="Static")))
    acceptance.record("download_fpr", fpr.ready or fpr.status == "RepositoryUpdating", str(fpr.status), size_bytes=fpr.size_bytes)

    export_batches = collect_stream(connector, "data_exports", mode="full")
    export_records = [record for batch in export_batches for record in batch.records]
    exports = map_all(connector, "data_exports", export_records)
    acceptance.record(
        "data_exports_complete_snapshot",
        bool(export_batches and export_batches[-1].complete),
        f"{len(export_records)} export jobs",
        downloaded=sum(1 for export in exports if export.ready),
    )
    if "data_export_id" in acceptance.params:
        export_id = str(acceptance.params["data_export_id"])
        download = asyncio.run(connector.download_data_export(DataExportArgs(data_export_id=export_id)))
        acceptance.record(
            "download_data_export",
            download.ready or download.status in ("Queued", "Started", "Failed", "RepositoryUpdating"),
            str(download.status),
            size_bytes=download.size_bytes,
        )
    if "report_id" in acceptance.params:
        report_id = str(acceptance.params["report_id"])
        vendor_report = asyncio.run(connector.get_report(ReportArgs(report_id=report_id)))
        download = asyncio.run(connector.download_report(ReportArgs(report_id=report_id)))
        acceptance.record("report_poll_and_download", bool(vendor_report.record), str(download.status), size_bytes=download.size_bytes)


def test_offline_openapi_fixture_replay(acceptance) -> None:
    connector = _connector(acceptance)
    fixture_dir = Path(__file__).resolve().parents[1] / "fixtures" / "fortify_fod"
    issue_page = json.loads((fixture_dir / "issues_page1.json").read_text(encoding="utf-8"))
    scan_page = json.loads((fixture_dir / "scans_page1.json").read_text(encoding="utf-8"))
    export_page = json.loads((fixture_dir / "data_exports_page1.json").read_text(encoding="utf-8"))
    findings = map_all(connector, "issues", [{**record, "_release_id": "42"} for record in issue_page["items"]])
    scans = map_all(connector, "scans", scan_page["items"])
    exports = map_all(
        connector,
        "data_exports",
        [{"job": record, "download": {"ready": False, "size_bytes": 0}} for record in export_page["items"]],
    )
    acceptance.record(
        "offline_fixture_replay",
        len(findings) == 3 and len(scans) == 2 and len(exports) == 2,
        "OpenAPI-shaped fixtures mapped",
        finding_statuses=[finding.status_id for finding in findings],
    )


def test_gated_bulk_issue_write(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    args = BulkAuditInput(release_id=str(acceptance.params["release_id"]), **acceptance.params["bulk_audit"])
    _plan, outcome = _run(connector, "bulk_audit_issues", args)
    acceptance.record("bulk_audit_issues", outcome.status in ("succeeded", "accepted_async"), outcome.status, result=outcome.result)


def test_gated_scan_import_and_report_writes(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    release_id = str(acceptance.params["release_id"])
    if "start_scan" in acceptance.params:
        encoded, sha256, size = _payload(str(acceptance.params["start_scan"]["payload_path"]))
        fields = {key: value for key, value in acceptance.params["start_scan"].items() if key != "payload_path"}
        args = StartScanInput(
            release_id=release_id,
            payload_base64=encoded,
            payload_sha256=sha256,
            **fields,
        )
        _plan, outcome = _run(connector, "start_scan", args)
        acceptance.record("start_scan", outcome.status in ("succeeded", "accepted_async"), outcome.status, result=outcome.result, payload_bytes=size)
    if "import_scan" in acceptance.params:
        encoded, sha256, size = _payload(str(acceptance.params["import_scan"]["payload_path"]))
        args = ImportScanInput(release_id=release_id, payload_base64=encoded, payload_sha256=sha256)
        _plan, outcome = _run(connector, "import_scan", args)
        acceptance.record("import_scan", outcome.status in ("succeeded", "accepted_async"), outcome.status, result=outcome.result, payload_bytes=size)
    if "create_report" in acceptance.params:
        args = CreateReportInput(release_id=release_id, **acceptance.params["create_report"])
        _plan, outcome = _run(connector, "create_report", args)
        acceptance.record("create_report", outcome.status in ("succeeded", "accepted_async"), outcome.status, result=outcome.result)


def test_separately_gated_destructive_writes(acceptance) -> None:
    acceptance.require_writes()
    if not acceptance.params.get("allow_destructive", False):
        pytest.skip("fortify_fod: allow_destructive is false in the acceptance file")
    connector = _connector(acceptance)
    release_id = str(acceptance.params["release_id"])
    if "cancel_scan_id" in acceptance.params:
        args = CancelScanInput(
            release_id=release_id,
            scan_id=str(acceptance.params["cancel_scan_id"]),
            approval_ref=str(acceptance.params["approval_ref"]),
        )
        _plan, outcome = _run(connector, "cancel_scan", args)
        acceptance.record("cancel_scan", outcome.status in ("succeeded", "accepted_async"), outcome.status, result=outcome.result)
    if "delete_resource" in acceptance.params:
        args = DeleteResourceInput(
            **acceptance.params["delete_resource"],
            approval_ref=str(acceptance.params["approval_ref"]),
        )
        _plan, outcome = _run(connector, "delete_release_application_report", args)
        acceptance.record("delete_release_application_report", outcome.status in ("succeeded", "accepted_async"), outcome.status, result=outcome.result)
