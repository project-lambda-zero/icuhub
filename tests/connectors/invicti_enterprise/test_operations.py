"""Invicti Enterprise typed read-operation tests."""

from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from datetime import UTC, datetime

from icuhub.connectors.invicti_enterprise.models import (
    DownloadReportArgs,
    EmptyArgs,
    IssueArgs,
    ListIssuesArgs,
    ListScansArgs,
    ScanArgs,
    WebsiteArgs,
)

from .conftest import enterprise_connector, load_fixture


def test_all_read_operations_use_vendor_shapes_and_bounded_evidence() -> None:
    issue = deepcopy(load_fixture("issues.json")["List"][0])
    issue["HttpRequest"] = "GET /?token=read-secret HTTP/1.1\r\nAuthorization: Bearer header-secret"
    scan = load_fixture("scans.json")["List"][0]
    report = load_fixture("report.json")
    routes = {
        ("GET", "/api/1.0/issues/allissues"): {"status": 200, "json": {**load_fixture("issues.json"), "List": [issue]}},
        ("GET", "/api/1.0/scans/list"): {"status": 200, "json": load_fixture("scans.json")},
        ("GET", "/api/1.0/scans/listbystatechanged"): {"status": 200, "json": load_fixture("scans.json")},
        ("GET", f"/api/1.0/issues/{issue['Id']}"): {"status": 200, "json": issue},
        ("GET", f"/api/1.0/issues/{issue['Id']}/history"): {"status": 200, "json": [{"State": "Present"}]},
        ("GET", f"/api/1.0/websites/{issue['WebsiteId']}"): {
            "status": 200,
            "json": {"Id": issue["WebsiteId"], "Name": "Shop", "RootUrl": issue["WebsiteRootUrl"], "Groups": [{"Name": "Production"}]},
        },
        ("GET", f"/api/1.0/scans/{scan['Id']}"): {"status": 200, "json": scan},
        ("GET", f"/api/1.0/scans/result/{scan['Id']}"): {"status": 200, "text": json.dumps(load_fixture("scan_results.json"))},
        ("GET", "/api/1.0/scans/report"): {"status": 200, "text": json.dumps(report)},
        ("GET", "/api/1.0/notifications"): {
            "status": 200,
            "json": {"List": [{"Id": "notification-1", "Name": "Issues", "Event": "IssueUpdated", "Scope": "Website", "Secret": "do-not-return"}]},
        },
    }
    connector = enterprise_connector(routes)

    listed = asyncio.run(connector.list_issues(ListIssuesArgs(page_size=1)))
    assert listed.issues[0].id == issue["Id"]
    assert "read-secret" not in str(listed.model_dump())
    scans = asyncio.run(connector.list_scans(ListScansArgs()))
    assert scans.scans[0].completed is True
    windowed = asyncio.run(
        connector.list_scans(
            ListScansArgs(
                state_changed_start=datetime(2026, 11, 1, tzinfo=UTC),
                state_changed_end=datetime(2026, 11, 2, tzinfo=UTC),
            )
        )
    )
    assert windowed.scans[0].id == scan["Id"]
    detail = asyncio.run(connector.get_issue(IssueArgs(issue_id=issue["Id"])))
    assert detail.evidence.http_request.redacted is True
    assert "header-secret" not in str(detail.model_dump())
    history = asyncio.run(connector.get_issue_history(IssueArgs(issue_id=issue["Id"])))
    assert history.history == [{"State": "Present"}]
    website = asyncio.run(connector.get_website(WebsiteArgs(website_id=issue["WebsiteId"])))
    assert website.groups == ["Production"]
    scan_detail = asyncio.run(connector.get_scan(ScanArgs(scan_id=scan["Id"])))
    assert scan_detail.scan.id == scan["Id"]
    results = asyncio.run(connector.get_scan_result(ScanArgs(scan_id=scan["Id"])))
    assert results.results[0].scan_id == scan["Id"]
    downloaded = asyncio.run(connector.download_report(DownloadReportArgs(scan_id=scan["Id"])))
    assert downloaded.report.report_id == "report-enterprise-001"
    assert downloaded.evidence
    notifications = asyncio.run(connector.list_notifications(EmptyArgs()))
    assert notifications.notifications[0].id == "notification-1"
    assert "do-not-return" not in str(notifications.model_dump())


def test_health_reports_identity_and_unprobed_manage_permission() -> None:
    connector = enterprise_connector(
        {("GET", "/api/1.0/issues/allissues"): {"status": 200, "json": load_fixture("issues.json")}}
    )
    report = asyncio.run(connector.check())
    assert report.status == "healthy"
    assert report.detail["manage_issue"] == "not_evaluated"
