"""Live Invicti Enterprise acceptance for reads and optional governed triage."""

from __future__ import annotations

import asyncio

import httpx2

from icuhub.connectors.invicti_enterprise import InvictiEnterprise
from icuhub.connectors.invicti_enterprise.models import (
    DownloadReportArgs,
    EmptyArgs,
    IssueArgs,
    ListIssuesArgs,
    ListScansArgs,
    ScanArgs,
    UpdateIssueInput,
    WebsiteArgs,
)
from icuhub.kit.testing import make_connector

ACCEPTANCE_KIND = "invicti_enterprise"


def _connector(acceptance) -> InvictiEnterprise:
    return make_connector(InvictiEnterprise, acceptance.config, httpx2.AsyncHTTPTransport(), acceptance.secrets)


def test_health_and_paged_reads(acceptance) -> None:
    connector = _connector(acceptance)
    health = asyncio.run(connector.check())
    acceptance.record("health", health.status in {"healthy", "degraded"}, health.status)
    issues = asyncio.run(connector.list_issues(ListIssuesArgs(page=1, page_size=1)))
    acceptance.record("list_issues", True, f"{len(issues.issues)} issue on first page")
    scans = asyncio.run(connector.list_scans(ListScansArgs(page=1, page_size=1)))
    acceptance.record("list_scans", True, f"{len(scans.scans)} scan on first page")
    notifications = asyncio.run(connector.list_notifications(EmptyArgs()))
    acceptance.record("list_notifications", True, f"{len(notifications.notifications)} notifications")


def test_detail_and_report_reads(acceptance) -> None:
    connector = _connector(acceptance)
    issue_id = acceptance.params.get("issue_id")
    if issue_id:
        detail = asyncio.run(connector.get_issue(IssueArgs(issue_id=issue_id)))
        acceptance.record("get_issue", detail.issue.id == issue_id, issue_id)
        history = asyncio.run(connector.get_issue_history(IssueArgs(issue_id=issue_id)))
        acceptance.record("get_issue_history", True, f"{len(history.history)} history entries")
    website_id = acceptance.params.get("website_id")
    if website_id:
        website = asyncio.run(connector.get_website(WebsiteArgs(website_id=website_id)))
        acceptance.record("get_website", website.website.id == website_id, website_id)
    scan_id = acceptance.params.get("scan_id")
    if scan_id:
        scan = asyncio.run(connector.get_scan(ScanArgs(scan_id=scan_id)))
        acceptance.record("get_scan", scan.scan.id == scan_id, scan_id)
        result = asyncio.run(connector.get_scan_result(ScanArgs(scan_id=scan_id)))
        acceptance.record("get_scan_result", True, f"{len(result.results)} scan results")
        report = asyncio.run(connector.download_report(DownloadReportArgs(scan_id=scan_id)))
        acceptance.record("download_report", bool(report.report.snapshot.snapshot_id), report.report.report_id)


def test_optional_update_issue(acceptance) -> None:
    issue_id = acceptance.params.get("triage_issue_id")
    if not issue_id:
        acceptance.record("update_issue", True, "not_evaluated: triage_issue_id not configured")
        return
    acceptance.require_writes()
    desired_state = acceptance.params["triage_state"]
    current = asyncio.run(_connector(acceptance).get_issue(IssueArgs(issue_id=issue_id)))
    if current.issue.last_seen is None:
        raise AssertionError("triage issue has no LastSeenDate")
    args = UpdateIssueInput(
        issue_id=issue_id,
        expected_last_seen=current.issue.last_seen,
        expected_state=current.issue.state,
        state=desired_state,
    )
    connector = _connector(acceptance)
    plan = asyncio.run(connector.plan_update_issue(args))
    outcome = asyncio.run(connector.apply_update_issue(plan))
    acceptance.record("update_issue", outcome.status in {"succeeded", "no_op"}, outcome.status)
    assert outcome.status in {"succeeded", "no_op"}
