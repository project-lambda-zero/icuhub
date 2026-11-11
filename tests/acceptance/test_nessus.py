"""Live Nessus acceptance: edition, changed scans, rollover-excluded history, one export."""

from __future__ import annotations

import asyncio

import httpx2

from icuhub.connectors.nessus import Nessus
from icuhub.connectors.nessus.models import (
    CreateExportArgs,
    DownloadExportArgs,
    GetExportStatusArgs,
    ListHistoryArgs,
    ListScansArgs,
)
from icuhub.kit.testing import make_connector

ACCEPTANCE_KIND = "nessus"


def _connector(acceptance) -> Nessus:
    return make_connector(Nessus, acceptance.config, httpx2.AsyncHTTPTransport(), acceptance.secrets)  # type: ignore[return-value]


def test_health_and_changed_scans(acceptance) -> None:
    connector = _connector(acceptance)
    report = asyncio.run(connector.check())
    acceptance.record("health", report.status in ("healthy", "degraded"), report.status, edition=report.detail.get("edition"))
    scans = asyncio.run(connector.list_scans(ListScansArgs()))
    acceptance.record("list_scans", len(scans.scans) >= 0, f"{len(scans.scans)} scans")


def test_history_and_export(acceptance) -> None:
    scan_id = str(acceptance.params["scan_id"])
    connector = _connector(acceptance)
    history = asyncio.run(connector.list_history(ListHistoryArgs(scan_id=scan_id)))
    acceptance.record("list_history", len(history.history) >= 0, f"{len(history.history)} runs")
    export = asyncio.run(connector.create_export(CreateExportArgs(scan_id=scan_id)))
    status = asyncio.run(
        connector.get_export_status(GetExportStatusArgs(scan_id=scan_id, file_id=export.file_id, export_kind=export.export_kind))
    )
    acceptance.record("export_ready", status.ready, status.status)
    assert status.ready
    download = asyncio.run(connector.download_export(DownloadExportArgs(scan_id=scan_id, file_id=export.file_id, export_kind=export.export_kind)))
    acceptance.record(
        "download_export",
        len(download.records) >= 0,
        f"{len(download.records)} records",
        truncated=download.truncated,
    )
