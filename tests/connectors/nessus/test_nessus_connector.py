"""Offline Nessus connector tests: auth, operations, export streams, import, health."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from icuhub.connectors.nessus import Nessus
from icuhub.connectors.nessus.models import (
    CreateExportArgs,
    DownloadExportArgs,
    ListHistoryArgs,
    ListScansArgs,
)
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import ImportedFile, Target
from icuhub_schemas.ocsf import ComplianceFinding, DetectionFinding, VulnerabilityFinding

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "nessus"
SCANS = {
    "scans": [
        {"id": 1, "name": "weekly", "uuid": "u-1", "status": "completed", "last_modification_date": 1700000000},
        {"id": 2, "name": "ad-hoc", "uuid": "u-2", "status": "running", "last_modification_date": 1700000100},
    ],
    "folders": [{"id": 3, "name": "ops"}],
}
HISTORY = {"history": [{"history_id": 11, "time_start": 1699999000, "time_end": 1700000000, "status": "completed"}]}


def _connector(edition: str = "Nessus Professional", auth_mode: str = "api_keys") -> Nessus:
    def download(request: Any) -> dict[str, Any]:
        return {"status": 200, "text": (FIXTURES / "sample_scan.nessus").read_text()}

    routes = {
        ("GET", "/scans"): {"status": 200, "json": SCANS},
        ("GET", "/scans/1/history"): {"status": 200, "json": HISTORY},
        ("POST", "/scans/1/export"): {"status": 200, "json": {"file": 77}},
        ("GET", "/scans/1/export/77/status"): {"status": 200, "json": {"status": "ready"}},
        ("GET", "/scans/1/export/77/download"): download,
        ("GET", "/server/properties"): {"status": 200, "json": {"version": "10.8.0", "edition": edition}},
        ("POST", "/session"): {"status": 200, "json": {"token": "session-token"}},
    }
    config: dict[str, Any] = {"base_url": "https://nessus.example.test", "auth_mode": auth_mode}
    secrets: dict[str, bytes] = {}
    if auth_mode == "api_keys":
        config.update({"access_key": {"ref": "a"}, "secret_key": {"ref": "s"}})
        secrets = {"a": b"access", "s": b"secret"}
    else:
        config.update({"username": "admin", "password": {"ref": "p"}, "export_poll_interval_s": 0})
        secrets = {"p": b"pw"}
    return make_connector(Nessus, config, RouteTransport(routes), secrets)  # type: ignore[return-value]


TARGET = Target(id="1", source_uid="1", kind="scan", display_name="weekly", attributes={})


def test_scans_and_history_operations() -> None:
    connector = _connector()
    scans = asyncio.run(connector.list_scans(ListScansArgs(last_modification_date=1700000000)))
    assert len(scans.scans) == 2 and scans.folders[0]["name"] == "ops"
    history = asyncio.run(connector.list_history(ListHistoryArgs(scan_id="1")))
    assert history.history[0].history_id == 11
    assert history.exclude_rollover is True


def test_session_auth_and_export_operations() -> None:
    connector = _connector(auth_mode="username_password_session")
    export = asyncio.run(connector.create_export(CreateExportArgs(scan_id="1", history_id="11")))
    assert export.file_id == "77" and export.export_kind == "file"
    download = asyncio.run(connector.download_export(DownloadExportArgs(scan_id="1", file_id="77")))
    assert len(download.records) == 5
    assert download.report.source == "live"


def test_export_findings_stream_and_mapping() -> None:
    connector = _connector()
    (batch,) = collect_stream(connector, "export_findings", target=TARGET, mode="full")
    assert len(batch.records) == 5
    assert batch.complete is True
    assert batch.checkpoint.targets_done == ["app01.example.test", "db01.example.test", "web01.example.test"]
    mapped = map_all(connector, "export_findings", batch.records, target=TARGET)
    detections = [m for m in mapped if isinstance(m, DetectionFinding)]
    vulns = [m for m in mapped if isinstance(m, VulnerabilityFinding)]
    assert len(detections) == 1 and len(vulns) == 4
    assert {v.severity_id for v in vulns} == {2, 3, 4, 5}
    assert any(v.vulnerabilities[0].cve and v.vulnerabilities[0].cve.uid == "CVE-2026-1111" for v in vulns)
    assert any(v.vulnerabilities[0].cwe and v.vulnerabilities[0].cwe.uid == "CWE-89" for v in vulns)


def test_compliance_stream_and_mapping() -> None:
    connector = _connector()

    def download(request: Any) -> dict[str, Any]:
        return {"status": 200, "text": (FIXTURES / "compliance_scan.nessus").read_text()}

    connector.ctx.http._client._transport = RouteTransport(
        {
            ("POST", "/scans/1/export"): {"status": 200, "json": {"file": 77}},
            ("GET", "/scans/1/export/77/status"): {"status": 200, "json": {"status": "ready"}},
            ("GET", "/scans/1/export/77/download"): download,
        }
    )
    (batch,) = collect_stream(connector, "compliance_findings", target=TARGET, mode="full")
    assert len(batch.records) == 2
    mapped = map_all(connector, "compliance_findings", batch.records, target=TARGET)
    assert all(isinstance(m, ComplianceFinding) for m in mapped)
    assert mapped[0].compliance.checks[0].name.startswith("Check")
    assert mapped[0].compliance.standards == ["CIS|1.1.3001"]


def test_importers_and_replay_identity() -> None:
    connector = _connector()
    data = (FIXTURES / "sample_scan.nessus").read_bytes()

    async def gather() -> list[dict[str, Any]]:
        return [r async for r in connector.import_nessus_xml(ImportedFile(filename="s.nessus", data=data))]

    first = asyncio.run(gather())
    second = asyncio.run(gather())
    assert len(first) == 5
    assert [r["event_uid"] for r in first] == [r["event_uid"] for r in second]
    assert first[0]["report"]["source"] == "upload"
    compliance_data = (FIXTURES / "compliance_scan.nessus").read_bytes()

    async def gather_compliance() -> list[dict[str, Any]]:
        return [r async for r in connector.import_nessus_compliance(ImportedFile(filename="c.nessus", data=compliance_data))]

    assert len(asyncio.run(gather_compliance())) == 2


def test_health_edition_gating() -> None:
    assert asyncio.run(_connector().check()).status == "healthy"
    report = asyncio.run(_connector(edition="Nessus Essentials").check())
    assert report.capabilities["export"].status == "not_evaluated"
    assert report.capabilities["FindingSource"].status == "not_evaluated"


def test_no_write_surface() -> None:
    assert not Nessus.actions()
    assert not Nessus.webhooks()
    assert Nessus.webhooks() == {}
