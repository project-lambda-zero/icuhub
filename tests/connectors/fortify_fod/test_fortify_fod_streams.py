from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors.fortify_fod import FortifyFod
from icuhub.connectors.fortify_fod.models import DataExportRecord, ScanRecord
from icuhub.kit.cursors import SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import TransientVendorError
from icuhub.kit.testing import RouteTransport, collect_stream, conformance_problems, make_connector, map_all
from icuhub.kit.types import Target

BASE = "https://api.ams.fortify.com"
CONFIG = {"base_url": BASE, "client_id": "client-1", "client_secret": {"ref": "fod_secret"}}
SECRETS = {"fod_secret": b"not-a-real-secret"}
TOKEN = {"status": 200, "json": {"access_token": "token-1", "expires_in": 3600}}
TARGET = Target(id="release-42", source_uid="42", kind="release", display_name="Release 42", attributes={})
EXPORTS = "/api/v3/reports/dataexports"


def _connector(routes: dict[tuple[str, str], Any]) -> Any:
    transport = RouteTransport({("POST", "/oauth/token"): TOKEN, **routes})
    connector = make_connector(FortifyFod, CONFIG, transport=transport, secrets=SECRETS)
    connector._test_transport = transport
    return connector


def _page(items: list[dict[str, Any]], *, offset: int = 0) -> dict[str, Any]:
    return {"status": 200, "json": {"items": items, "offset": offset, "totalCount": len(items)}}


def _scan(scan_id: int, timestamp: str) -> dict[str, Any]:
    return {"scanId": scan_id, "releaseId": 42, "analysisStatusType": "Completed", "modifiedDate": timestamp}


def _export(export_id: int, status: str = "Completed") -> dict[str, Any]:
    return {"dataExportId": export_id, "dataExportType": "IssuesExport", "dataExportStatusType": status}


def test_registered_surface_has_required_streams_and_six_actions() -> None:
    assert conformance_problems(FortifyFod) == []
    assert set(FortifyFod.streams()) == {"issues", "scans", "data_exports"}
    assert set(FortifyFod.actions()) == {
        "bulk_audit_issues",
        "start_scan",
        "import_scan",
        "create_report",
        "cancel_scan",
        "delete_release_application_report",
    }


def test_scan_stream_maps_typed_records_and_closes_absence_only_in_full_mode() -> None:
    records = [_scan(1, "2026-11-08T00:00:00Z"), _scan(2, "2026-11-09T00:00:00Z")]
    full_connector = _connector({("GET", "/api/v3/releases/42/scans"): _page(records)})
    incremental_connector = _connector({("GET", "/api/v3/releases/42/scans"): _page(records)})

    full = collect_stream(full_connector, "scans", target=TARGET, mode="full")
    incremental = collect_stream(incremental_connector, "scans", target=TARGET, mode="incremental")
    mapped = map_all(full_connector, "scans", records)

    assert full[-1].complete is True
    assert incremental[-1].complete is False
    assert full[-1].checkpoint == TimeIdCursor(
        ts=datetime(2026, 11, 9, tzinfo=UTC), last_ids_at_ts=["2"]
    )
    assert mapped == [
        ScanRecord(
            scan_id=1,
            release_id=42,
            analysis_status="Completed",
            observed_at=datetime(2026, 11, 8, tzinfo=UTC),
        ),
        ScanRecord(
            scan_id=2,
            release_id=42,
            analysis_status="Completed",
            observed_at=datetime(2026, 11, 9, tzinfo=UTC),
        ),
    ]


def test_data_export_stream_downloads_before_advancing_snapshot_cursor() -> None:
    content = b"completed-export"
    connector = _connector(
        {
            ("GET", EXPORTS): _page([_export(3), _export(4, "Queued")]),
            ("GET", f"{EXPORTS}/3/download"): {"status": 200, "content": content},
        }
    )

    batches = collect_stream(connector, "data_exports", mode="full")
    checkpoint = batches[0].checkpoint
    mapped = map_all(connector, "data_exports", batches[0].records)

    assert isinstance(checkpoint, SnapshotCursor)
    assert checkpoint.targets_done == ["3"]
    assert batches[0].records[0]["download"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert batches[1].records[0]["job"]["dataExportStatusType"] == "Queued"
    assert batches[1].records[0]["download"]["ready"] is False
    assert batches[-1].complete is True
    assert mapped == [
        DataExportRecord(
            data_export_id=3,
            data_export_type="IssuesExport",
            status="Completed",
            ready=True,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
        )
    ]


def test_data_export_partial_download_failure_resumes_without_redownloading_done_job() -> None:
    first = _connector(
        {
            ("GET", EXPORTS): _page([_export(3), _export(4)]),
            ("GET", f"{EXPORTS}/3/download"): {"status": 200, "content": b"first"},
            ("GET", f"{EXPORTS}/4/download"): {"status": 202, "json": {"state": "updating"}},
        }
    )

    async def fail_after_first() -> SnapshotCursor:
        stream = first.data_exports(None, None, "full")
        batch = await anext(stream)
        with pytest.raises(TransientVendorError, match="not downloadable"):
            await anext(stream)
        assert isinstance(batch.checkpoint, SnapshotCursor)
        return batch.checkpoint

    checkpoint = asyncio.run(fail_after_first())
    assert checkpoint.targets_done == ["3"]

    resumed = _connector(
        {
            ("GET", EXPORTS): _page([_export(3), _export(4)]),
            ("GET", f"{EXPORTS}/4/download"): {"status": 200, "content": b"second"},
        }
    )
    batches = collect_stream(resumed, "data_exports", checkpoint=checkpoint, mode="full")

    assert [batch.records[0]["job"]["dataExportId"] for batch in batches[:-1]] == [4]
    assert batches[-1].complete is True
    assert isinstance(batches[-1].checkpoint, SnapshotCursor)
    assert batches[-1].checkpoint.targets_done == ["3", "4"]
    assert not any(request.url.path == f"{EXPORTS}/3/download" for request in resumed._test_transport.requests)


def test_redacted_openapi_fixtures_replay_through_registered_mappers() -> None:
    fixture_dir = Path(__file__).resolve().parents[2] / "fixtures" / "fortify_fod"
    issue_page = json.loads((fixture_dir / "issues_page1.json").read_text(encoding="utf-8"))
    scan_page = json.loads((fixture_dir / "scans_page1.json").read_text(encoding="utf-8"))
    export_page = json.loads((fixture_dir / "data_exports_page1.json").read_text(encoding="utf-8"))
    connector = _connector({})

    findings = map_all(
        connector,
        "issues",
        [{**record, "_release_id": "42"} for record in issue_page["items"]],
    )
    scans = map_all(connector, "scans", scan_page["items"])
    exports = map_all(
        connector,
        "data_exports",
        [
            {"job": record, "download": {"ready": False, "sha256": None, "size_bytes": 0}}
            for record in export_page["items"]
        ],
    )

    assert [finding.status_id for finding in findings] == [1, 4, 3]
    assert findings[0].finding_info.uid == "fortify_fod:release:42:instance:instance-0001"
    assert findings[0].vulnerabilities[0].cwe.uid == "CWE-89"
    assert [scan.scan_id for scan in scans] == [501, 502]
    assert [export.status for export in exports] == ["Completed", "Queued"]
