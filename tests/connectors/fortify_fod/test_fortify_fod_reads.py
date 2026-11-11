from __future__ import annotations

import asyncio
import base64
import hashlib
from datetime import UTC, datetime
from typing import Any

from icuhub.connectors.fortify_fod import FortifyFod
from icuhub.connectors.fortify_fod.models import (
    ApplicationArgs,
    DataExportArgs,
    DownloadFprArgs,
    EmptyArgs,
    IssueArgs,
    IssueHistoryArgs,
    IssueInstanceArgs,
    ListApplicationsArgs,
    ListDataExportsArgs,
    ListReleasesArgs,
    ListScansArgs,
    MicroservicesArgs,
    ReleaseArgs,
    ReleaseScanArgs,
    ReportArgs,
)
from icuhub.kit.testing import RouteTransport, make_connector

BASE = "https://api.ams.fortify.com"
VULNS = "/api/v3/releases/42/vulnerabilities"
CONFIG = {"base_url": BASE, "client_id": "client-1", "client_secret": {"ref": "fod_secret"}}
SECRETS = {"fod_secret": b"not-a-real-secret"}
TOKEN = {"status": 200, "json": {"access_token": "token-1", "expires_in": 3600}}


def _connector(routes: dict[tuple[str, str], Any]) -> Any:
    transport = RouteTransport({("POST", "/oauth/token"): TOKEN, **routes})
    connector = make_connector(FortifyFod, CONFIG, transport=transport, secrets=SECRETS)
    connector._test_transport = transport
    return connector


def _page(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"status": 200, "json": {"items": items, "offset": 0, "totalCount": len(items)}}


def test_probe_target_accepts_documented_collection_responses() -> None:
    connector = _connector(
        {
            ("GET", "/api/v3/tenants"): {"status": 200, "json": {"tenantId": 7, "tenantCode": "tenant-7"}},
            ("GET", "/api/v3/tenants/features"): {"status": 200, "json": [{"featureKey": "issues"}]},
            ("GET", "/api/v3/tenant-entitlements"): {"status": 200, "json": [{"entitlementId": 9}]},
            ("GET", "/api/v3/applications"): _page([]),
        }
    )

    output = asyncio.run(connector.probe_target(EmptyArgs()))
    health = asyncio.run(connector.check())

    assert output.record["features"] == [{"featureKey": "issues"}]
    assert output.record["entitlements"] == [{"entitlementId": 9}]
    assert output.record["oauth_scope"] == "api-tenant"
    assert health.status == "healthy"


def test_application_release_and_microservice_reads() -> None:
    connector = _connector(
        {
            ("GET", "/api/v3/applications"): _page([{"applicationId": 7, "applicationName": "app"}]),
            ("GET", "/api/v3/applications/7"): {"status": 200, "json": {"applicationId": 7}},
            ("GET", "/api/v3/applications/7/microservices"): {
                "status": 200,
                "json": {"items": [{"microserviceId": 2}], "totalCount": 1},
            },
            ("GET", "/api/v3/releases"): _page([{"releaseId": 42}]),
            ("GET", "/api/v3/releases/42"): {"status": 200, "json": {"releaseId": 42}},
        }
    )
    modified = datetime(2026, 11, 9, tzinfo=UTC)

    applications = asyncio.run(connector.list_applications(ListApplicationsArgs(modified_since=modified)))
    application = asyncio.run(connector.get_application(ApplicationArgs(application_id="7")))
    microservices = asyncio.run(connector.list_microservices(MicroservicesArgs(application_id="7")))
    releases = asyncio.run(connector.list_releases(ListReleasesArgs(modified_since=modified)))
    release = asyncio.run(connector.get_release(ReleaseArgs(release_id="42")))

    assert applications.records[0]["applicationId"] == 7
    assert application.record == {"applicationId": 7}
    assert microservices.total_count == 1
    assert releases.records == [{"releaseId": 42}]
    assert release.record == {"releaseId": 42}
    assert isinstance(connector._test_transport, RouteTransport)
    requests = connector._test_transport.requests
    assert requests[1].url.params["modifiedStartDate"] == modified.isoformat()
    assert requests[4].url.params["modifiedStartDate"] == modified.isoformat()


def test_issue_reads_use_bounded_bounded_endpoints_and_include_all_states() -> None:
    instance = {"id": 10001, "instanceId": "instance-1", "issueName": "SQL Injection"}
    connector = _connector(
        {
            ("GET", VULNS): _page([instance]),
            ("GET", f"{VULNS}/10001/details"): {"status": 200, "json": {"details": {"summary": "detail"}}},
            ("GET", f"{VULNS}/10001/history"): {"status": 200, "json": {"items": []}},
            ("GET", f"{VULNS}/10001/recommendations"): {"status": 200, "json": {"recommendations": []}},
        }
    )
    args = IssueArgs(release_id="42", vuln_id="10001")

    issue = asyncio.run(connector.get_issue(IssueInstanceArgs(release_id="42", instance_id="instance-1")))
    details = asyncio.run(connector.get_issue_details(args))
    history = asyncio.run(connector.get_issue_history(IssueHistoryArgs(release_id="42", vuln_id="10001")))
    recommendations = asyncio.run(connector.get_recommendations(args))

    assert issue.record["_release_id"] == "42"
    assert details.record["details"]["summary"] == "detail"
    assert history.record == {"items": []}
    assert recommendations.record == {"recommendations": []}
    lookup = connector._test_transport.requests[1]
    assert lookup.url.params["filters"] == "instanceId:instance-1"
    assert lookup.url.params["includeFixed"] == "true"
    assert lookup.url.params["includeSuppressed"] == "true"
    assert lookup.url.params["limit"] == "2"
    assert connector._test_transport.requests[3].url.params["includeSystemEvents"] == "false"


def test_scan_reads_include_release_scans_without_invented_vendor_delta() -> None:
    seen: list[Any] = []

    def release_scans(request: Any) -> dict[str, Any]:
        seen.append(request)
        return _page(
            [
                {"scanId": 1, "releaseId": 42, "modifiedDate": "2026-11-08T00:00:00Z"},
                {"scanId": 2, "releaseId": 42, "modifiedDate": "2026-11-10T00:00:00Z"},
            ]
        )

    connector = _connector(
        {
            ("GET", "/api/v3/releases/42/scans"): release_scans,
            ("GET", "/api/v3/releases/42/scans/2"): {"status": 200, "json": {"scanId": 2, "analysisStatusType": "Completed"}},
        }
    )

    listed = asyncio.run(
        connector.list_scans(ListScansArgs(release_id="42", modified_since=datetime(2026, 11, 9, tzinfo=UTC)))
    )
    scan = asyncio.run(connector.get_scan(ReleaseScanArgs(release_id="42", scan_id="2")))

    assert [record["scanId"] for record in listed.records] == [2]
    assert scan.record["analysisStatusType"] == "Completed"
    assert "modifiedStartDate" not in seen[0].url.params


def test_fpr_downloads_distinguish_content_from_repository_updating() -> None:
    content = b"fpr-bytes"
    connector = _connector(
        {
            ("GET", "/api/v3/scans/2/fpr"): {"status": 200, "content": content},
            ("GET", "/api/v3/releases/42/fpr"): {"status": 202, "json": {"state": "updating"}},
        }
    )

    ready = asyncio.run(connector.download_fpr(DownloadFprArgs(release_id="42", scan_id="2")))
    pending = asyncio.run(connector.download_fpr(DownloadFprArgs(release_id="42", scan_type="Static")))

    assert ready.ready is True
    assert ready.sha256 == hashlib.sha256(content).hexdigest()
    assert base64.b64decode(ready.content_base64 or "") == content
    assert pending.ready is False
    assert pending.status == "RepositoryUpdating"
    assert pending.content_base64 is None
    assert connector._test_transport.requests[2].url.params["scanType"] == "Static"


def test_report_and_data_export_downloads_poll_before_reading_bytes() -> None:
    connector = _connector(
        {
            ("GET", "/api/v3/reports/8"): {"status": 200, "json": {"reportId": 8, "isReceived": True}},
            ("GET", "/api/v3/reports/8/download"): {"status": 200, "content": b"report"},
            ("GET", "/api/v3/reports/dataexports"): _page(
                [
                    {"dataExportId": 3, "dataExportType": "IssuesExport", "dataExportStatusType": "Completed"},
                    {"dataExportId": 4, "dataExportType": "ScansExport", "dataExportStatusType": "Queued"},
                ]
            ),
            ("GET", "/api/v3/reports/dataexports/3/download"): {"status": 200, "content": b"issues"},
        }
    )

    report = asyncio.run(connector.get_report(ReportArgs(report_id="8")))
    report_download = asyncio.run(connector.download_report(ReportArgs(report_id="8")))
    jobs = asyncio.run(connector.list_data_exports(ListDataExportsArgs(data_export_type="ScansExport")))
    completed = asyncio.run(connector.download_data_export(DataExportArgs(data_export_id="3")))
    queued = asyncio.run(connector.download_data_export(DataExportArgs(data_export_id="4")))

    assert report.record["isReceived"] is True
    assert report_download.sha256 == hashlib.sha256(b"report").hexdigest()
    assert [record["dataExportId"] for record in jobs.records] == [4]
    assert completed.ready is True
    assert base64.b64decode(completed.content_base64 or "") == b"issues"
    assert queued.ready is False
    assert queued.status == "Queued"
