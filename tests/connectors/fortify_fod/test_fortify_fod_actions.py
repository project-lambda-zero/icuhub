from __future__ import annotations

import asyncio
import base64
import hashlib
from collections import deque
from typing import Any

import pytest

from icuhub.connectors.fortify_fod import FortifyFod
from icuhub.connectors.fortify_fod.models import (
    BulkAuditInput,
    CancelScanInput,
    CreateReportInput,
    DeleteResourceInput,
    ImportScanInput,
    StartScanInput,
)
from icuhub.kit.errors import PermissionDenied, StalePlan
from icuhub.kit.testing import RouteTransport, make_connector
from icuhub.kit.types import ActionOutcome

BASE = "https://api.ams.fortify.com"
SECRETS = {"fod_secret": b"not-a-real-secret"}
TOKEN = {"status": 200, "json": {"access_token": "token-1", "expires_in": 3600}}
PAYLOAD = b"fpr-payload"
PAYLOAD_B64 = base64.b64encode(PAYLOAD).decode("ascii")
PAYLOAD_SHA = hashlib.sha256(PAYLOAD).hexdigest()


def _config(**overrides: Any) -> dict[str, Any]:
    return {
        "base_url": BASE,
        "client_id": "client-1",
        "client_secret": {"ref": "fod_secret"},
        "write_enabled": True,
        **overrides,
    }


def _connector(routes: dict[tuple[str, str], Any], **config: Any) -> Any:
    transport = RouteTransport({("POST", "/oauth/token"): TOKEN, **routes})
    connector = make_connector(FortifyFod, _config(**config), transport=transport, secrets=SECRETS)
    connector._test_transport = transport
    return connector


def _page(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"status": 200, "json": {"items": items, "offset": 0, "totalCount": len(items)}}


def _queued(responses: list[dict[str, Any]]) -> Any:
    queue = deque(responses)

    def respond(request: Any) -> dict[str, Any]:
        assert queue, f"unexpected extra request to {request.url.path}"
        return queue.popleft()

    return respond


def _scan(status: str, scan_id: int = 501) -> dict[str, Any]:
    return {
        "scanId": scan_id,
        "releaseId": 42,
        "analysisStatusType": status,
        "modifiedDate": "2026-11-10T00:00:00Z",
    }


def test_write_actions_are_default_off() -> None:
    connector = _connector({}, write_enabled=False)

    with pytest.raises(PermissionDenied, match="write_enabled"):
        asyncio.run(
            connector.plan_bulk_audit(
                BulkAuditInput(release_id="42", vulnerability_ids=["10001"], developer_status="Resolved")
            )
        )
    assert connector._test_transport.requests == []


def test_destructive_actions_require_separate_opt_in() -> None:
    connector = _connector({})

    with pytest.raises(PermissionDenied, match="destructive_enabled"):
        asyncio.run(
            connector.plan_cancel_scan(CancelScanInput(release_id="42", scan_id="501", approval_ref="change-1"))
        )
    assert connector._test_transport.requests == []


def test_start_scan_persists_scan_id_and_reconciles_without_second_upload() -> None:
    start_path = "/api/v3/releases/42/static-scans/start-scan"
    scan_path = "/api/v3/releases/42/scans/501"
    connector = _connector(
        {
            ("GET", "/api/v3/releases/42/assessment-types"): _page([{"assessmentTypeId": 11}]),
            ("GET", "/api/v3/tenant-entitlements"): {"status": 200, "json": [{"entitlementId": 9}]},
            ("GET", "/api/v3/releases/42/scans"): _queued([_page([]), _page([])]),
            ("POST", start_path): {"status": 200, "json": {"scanId": 501}},
            ("GET", scan_path): _queued(
                [
                    {"status": 200, "json": _scan("InProgress")},
                    {"status": 200, "json": _scan("Completed")},
                ]
            ),
        }
    )
    args = StartScanInput(
        release_id="42",
        assessment_type_id=11,
        entitlement_id=9,
        entitlement_frequency_type="Subscription",
        profile={"technology_stack": "Java/J2EE"},
        billable_acknowledged=True,
        payload_base64=PAYLOAD_B64,
        payload_sha256=PAYLOAD_SHA,
    )

    plan = asyncio.run(connector.plan_start_scan(args))
    accepted = asyncio.run(connector.apply_start_scan(plan))
    completed = asyncio.run(connector.reconcile_start_scan(plan, accepted))

    assert plan.preconditions["previous_scan_ids"] == []
    assert plan.preconditions["payload_sha256"] == PAYLOAD_SHA
    assert accepted.status == "accepted_async"
    assert accepted.result["scan_id"] == 501
    assert completed.status == "succeeded"
    assert completed.result["status"] == "Completed"
    writes = [request for request in connector._test_transport.requests if request.method == "POST" and request.url.path == start_path]
    assert len(writes) == 1
    assert writes[0].content == PAYLOAD
    assert writes[0].url.params["fragNo"] == "0"
    assert writes[0].url.params["offset"] == "0"


def test_start_scan_refuses_nonterminal_existing_scan_before_write() -> None:
    connector = _connector(
        {
            ("GET", "/api/v3/releases/42/assessment-types"): _page([{"assessmentTypeId": 11}]),
            ("GET", "/api/v3/tenant-entitlements"): {"status": 200, "json": [{"entitlementId": 9}]},
            ("GET", "/api/v3/releases/42/scans"): _page([_scan("InProgress")]),
        }
    )

    with pytest.raises(StalePlan, match="not terminal"):
        asyncio.run(
            connector.plan_start_scan(
                StartScanInput(
                    release_id="42",
                    assessment_type_id=11,
                    entitlement_id=9,
                    entitlement_frequency_type="Subscription",
                    profile={"technology_stack": "Java/J2EE"},
                    billable_acknowledged=True,
                    payload_base64=PAYLOAD_B64,
                    payload_sha256=PAYLOAD_SHA,
                )
            )
        )
    assert not any(request.url.path.endswith("start-scan") for request in connector._test_transport.requests)


def test_import_scan_recovers_missing_scan_id_from_previous_scan_set() -> None:
    import_path = "/api/v3/releases/42/static-scans/import-scan"
    scans_path = "/api/v3/releases/42/scans"
    scan_path = f"{scans_path}/501"
    connector = _connector(
        {
            ("GET", "/api/v3/releases/42/import-scan-session-id"): {
                "status": 200,
                "json": {"importScanSessionId": "session-1"},
            },
            ("GET", scans_path): _queued([_page([]), _page([_scan("InProgress")])]),
            ("PUT", import_path): {"status": 200, "json": {"referenceId": "import-1"}},
            ("GET", scan_path): _queued(
                [
                    {"status": 200, "json": _scan("InProgress")},
                    {"status": 200, "json": _scan("Completed")},
                ]
            ),
        }
    )

    plan = asyncio.run(
        connector.plan_import_scan(
            ImportScanInput(release_id="42", payload_base64=PAYLOAD_B64, payload_sha256=PAYLOAD_SHA)
        )
    )
    accepted = asyncio.run(connector.apply_import_scan(plan))
    completed = asyncio.run(connector.reconcile_import_scan(plan, accepted))

    assert plan.idempotency_key == f"import_scan:42:{PAYLOAD_SHA}"
    assert plan.request["params"]["importScanSessionId"] == "session-1"
    assert accepted.status == "accepted_async"
    assert accepted.result["scan_id"] == 501
    assert accepted.result["reference_id"] == "import-1"
    assert completed.status == "succeeded"
    uploads = [request for request in connector._test_transport.requests if request.method == "PUT"]
    assert len(uploads) == 1
    assert uploads[0].content == PAYLOAD
    assert uploads[0].url.params["fileLength"] == str(len(PAYLOAD))
    assert uploads[0].url.params["fragNo"] == "0"


def test_import_post_write_read_failure_keeps_recovery_state_without_reupload() -> None:
    import_path = "/api/v3/releases/42/static-scans/import-scan"
    scans_path = "/api/v3/releases/42/scans"
    scan_reads = 0

    def scan_listing(request: Any) -> dict[str, Any]:
        nonlocal scan_reads
        scan_reads += 1
        return _page([]) if scan_reads == 1 else {"status": 500, "json": {"error": "unavailable"}}

    connector = _connector(
        {
            ("GET", "/api/v3/releases/42/import-scan-session-id"): {
                "status": 200,
                "json": {"importScanSessionId": "session-1"},
            },
            ("GET", scans_path): scan_listing,
            ("PUT", import_path): {"status": 200, "json": {"referenceId": "import-1"}},
        }
    )
    plan = asyncio.run(
        connector.plan_import_scan(
            ImportScanInput(release_id="42", payload_base64=PAYLOAD_B64, payload_sha256=PAYLOAD_SHA)
        )
    )

    outcome = asyncio.run(connector.apply_import_scan(plan))

    assert outcome.status == "outcome_unknown"
    assert outcome.result["previous_scan_ids"] == []
    assert outcome.result["import_scan_session_id"] == "session-1"
    assert outcome.result["reference_id"] == "import-1"
    assert len([request for request in connector._test_transport.requests if request.method == "PUT"]) == 1


def test_create_report_polls_and_downloads_without_recreating_report() -> None:
    report_path = "/api/v3/reports/8"
    connector = _connector(
        {
            ("GET", "/api/v3/reports"): _page([]),
            ("POST", "/api/v3/reports"): {"status": 200, "json": {"success": True, "reportId": 8}},
            ("GET", report_path): _queued(
                [
                    {"status": 200, "json": {"reportId": 8, "reportStatusType": "Queued", "isReceived": False}},
                    {"status": 200, "json": {"reportId": 8, "reportStatusType": "Completed", "isReceived": True}},
                ]
            ),
            ("GET", f"{report_path}/download"): {"status": 200, "content": b"report-pdf"},
        }
    )
    args = CreateReportInput(
        application_id="7",
        release_id="42",
        report_template_type_id=3,
        report_format="Pdf",
        report_name="release-report",
    )

    plan = asyncio.run(connector.plan_create_report(args))
    accepted = asyncio.run(connector.apply_create_report(plan))
    completed = asyncio.run(connector.reconcile_create_report(plan, accepted))

    assert accepted.status == "accepted_async"
    assert accepted.result == {"report_id": 8, "status": "Queued"}
    assert completed.status == "succeeded"
    assert completed.result["sha256"] == hashlib.sha256(b"report-pdf").hexdigest()
    creations = [request for request in connector._test_transport.requests if request.method == "POST" and request.url.path == "/api/v3/reports"]
    assert len(creations) == 1


def test_create_report_recovers_missing_id_by_natural_fingerprint() -> None:
    report_path = "/api/v3/reports/8"
    existing = {"reportId": 8, "applicationId": 7, "releaseId": 42, "reportName": "release-report"}
    connector = _connector(
        {
            ("GET", "/api/v3/reports"): _queued([_page([]), _page([existing])]),
            ("POST", "/api/v3/reports"): {"status": 200, "json": {"success": True}},
            ("GET", report_path): {
                "status": 200,
                "json": {**existing, "reportStatusType": "Completed", "isReceived": True},
            },
            ("GET", f"{report_path}/download"): {"status": 200, "content": b"report-pdf"},
        }
    )
    args = CreateReportInput(
        application_id="7",
        release_id="42",
        report_template_type_id=3,
        report_format="Pdf",
        report_name="release-report",
    )
    plan = asyncio.run(connector.plan_create_report(args))

    unknown = asyncio.run(connector.apply_create_report(plan))
    recovered = asyncio.run(connector.reconcile_create_report(plan, unknown))

    assert unknown.status == "outcome_unknown"
    assert recovered.status == "succeeded"
    assert recovered.result["report_id"] == 8
    creations = [request for request in connector._test_transport.requests if request.method == "POST" and request.url.path == "/api/v3/reports"]
    assert len(creations) == 1


def test_cancel_scan_is_destructive_and_reconciles_cancellation() -> None:
    scan_path = "/api/v3/releases/42/scans/501"
    cancel_path = f"{scan_path}/cancel-scan"
    connector = _connector(
        {
            ("GET", scan_path): _queued(
                [
                    {"status": 200, "json": _scan("InProgress")},
                    {"status": 200, "json": _scan("InProgress")},
                    {"status": 200, "json": _scan("Canceled")},
                ]
            ),
            ("POST", cancel_path): {"status": 202, "json": {"success": True}},
        },
        destructive_enabled=True,
    )

    plan = asyncio.run(
        connector.plan_cancel_scan(CancelScanInput(release_id="42", scan_id="501", approval_ref="change-1"))
    )
    outcome = asyncio.run(connector.apply_cancel_scan(plan))

    assert outcome.status == "succeeded"
    assert outcome.result["status"] == "Canceled"
    cancellations = [request for request in connector._test_transport.requests if request.method == "POST" and request.url.path == cancel_path]
    assert len(cancellations) == 1


def test_delete_release_confirms_absence_without_second_delete() -> None:
    release_path = "/api/v3/releases/42"
    connector = _connector(
        {
            ("GET", release_path): _queued(
                [
                    {"status": 200, "json": {"releaseId": 42}},
                    {"status": 404, "json": {"error": "missing"}},
                    {"status": 404, "json": {"error": "missing"}},
                ]
            ),
            ("DELETE", release_path): {"status": 204},
        },
        destructive_enabled=True,
    )

    plan = asyncio.run(
        connector.plan_delete_resource(
            DeleteResourceInput(resource_type="release", resource_id="42", approval_ref="change-2")
        )
    )
    outcome = asyncio.run(connector.apply_delete_resource(plan))
    reconciled = asyncio.run(
        connector.reconcile_delete_resource(plan, ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref))
    )

    assert outcome.status == "succeeded"
    assert outcome.result == {"deleted": True}
    assert reconciled.status == "succeeded"
    deletions = [request for request in connector._test_transport.requests if request.method == "DELETE"]
    assert len(deletions) == 1
