"""Offline Nessus connector tests: auth, operations, export streams, import, health."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors.nessus import Nessus
from icuhub.connectors.nessus.models import (
    CreateExportArgs,
    DownloadExportArgs,
    ListHistoryArgs,
    ListScansArgs,
    NessusHistory,
    NessusHistoryList,
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


def _advisory_report(plugin_ids: list[tuple[int, str]]) -> str:
    items = "".join(
        f'<ReportItem port="443" svc_name="www" protocol="tcp" severity="{severity}" '
        f'pluginID="{plugin_id}" pluginName="Plugin {plugin_id}" pluginFamily="Web Servers">'
        f"<synopsis>Synopsis {plugin_id}</synopsis></ReportItem>"
        for plugin_id, severity in plugin_ids
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<NessusClientData_v2><Policy/><Report name="advisory">'
        f'<ReportHost name="web01.example.test"><HostProperties/>{items}</ReportHost>'
        "</Report></NessusClientData_v2>\n"
    )


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


def test_cve_and_cwe_on_one_item_map_without_validation_error() -> None:
    # Failing before the CVE-precedence fix: the shared Vulnerability model rejected both identifiers.
    connector = _connector()
    data = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<NessusClientData_v2><Policy/><Report name="scan">'
        b'<ReportHost name="web01.example.test"><HostProperties/>'
        b'<ReportItem port="443" svc_name="www" protocol="tcp" severity="3" pluginID="77" '
        b'pluginName="Both ids" pluginFamily="Web Servers">'
        b"<cve>CVE-2026-9999</cve><cwe>89</cwe></ReportItem></ReportHost>"
        b"</Report></NessusClientData_v2>\n"
    )
    records = connector._parse(data, scan_id=None, history_id=None, history_status=None, archived=None, source="upload").records
    (vuln,) = map_all(connector, "export_findings", records, target=TARGET)
    assert isinstance(vuln, VulnerabilityFinding)
    assert vuln.vulnerabilities[0].cve is not None
    assert vuln.vulnerabilities[0].cve.uid == "CVE-2026-9999"
    assert vuln.vulnerabilities[0].cwe is None
    assert vuln.unmapped["nessus"]["cwes"] == ["89"]


def test_same_scan_reexport_keeps_finding_identity_and_fingerprint() -> None:
    connector = _connector()
    base = (FIXTURES / "sample_scan.nessus").read_text()
    # A re-export of the same report differs in bytes (trailing whitespace) but not in identity.
    reexport = (base + "\n").encode()
    assert reexport != base.encode()
    first = connector._parse(base.encode(), scan_id=None, history_id=None, history_status=None, archived=None, source="upload").records
    second = connector._parse(reexport, scan_id=None, history_id=None, history_status=None, archived=None, source="upload").records
    assert [r.event_uid for r in first] == [r.event_uid for r in second]
    mapped_first = map_all(connector, "export_findings", first, target=TARGET)
    mapped_second = map_all(connector, "export_findings", second, target=TARGET)
    assert [m.finding_info.uid for m in mapped_first] == [m.finding_info.uid for m in mapped_second]
    fingerprints = [m.unmapped["icuhub"]["fingerprint"] for m in mapped_first]
    assert all(re.fullmatch(r"fp_[0-9a-f]{64}", fp) for fp in fingerprints)
    assert fingerprints == [m.unmapped["icuhub"]["fingerprint"] for m in mapped_second]


def test_different_port_on_same_host_and_plugin_gets_distinct_identity() -> None:
    connector = _connector()
    base = (FIXTURES / "sample_scan.nessus").read_text()
    moved = base.replace('port="443"', 'port="8443"', 1)
    first = connector._parse(base.encode(), scan_id=None, history_id=None, history_status=None, archived=None, source="upload").records
    second = connector._parse(moved.encode(), scan_id=None, history_id=None, history_status=None, archived=None, source="upload").records
    assert first[0].event_uid != second[0].event_uid


def test_live_scan_identity_is_scoped_by_scan_id() -> None:
    connector = _connector()
    data = (FIXTURES / "sample_scan.nessus").read_bytes()
    live = connector._parse(data, scan_id="1", history_id="11", history_status=None, archived=None, source="live").records
    again = connector._parse(data, scan_id="1", history_id="12", history_status=None, archived=None, source="live").records
    other_scan = connector._parse(data, scan_id="2", history_id="11", history_status=None, archived=None, source="live").records
    assert [r.event_uid for r in live] == [r.event_uid for r in again]
    assert [r.event_uid for r in live] != [r.event_uid for r in other_scan]


def test_history_archived_flag_maps_from_is_archived_key() -> None:
    history = NessusHistory.model_validate({"history_id": 11, "is_archived": True})
    assert history.archived is True
    assert history.history_id == 11


def test_live_export_carries_history_status_and_archived_from_listing() -> None:
    connector = _connector()
    listing = {"history": [{"history_id": 11, "status": "completed", "is_archived": True}]}
    connector.ctx.http._client._transport = RouteTransport(
        {
            ("GET", "/scans/1/history"): {"status": 200, "json": listing},
            ("GET", "/scans/1/export/77/download"): {"status": 200, "text": (FIXTURES / "sample_scan.nessus").read_text()},
        }
    )
    download = asyncio.run(connector.download_export(DownloadExportArgs(scan_id="1", file_id="77", history_id="11")))
    assert download.report.history_status == "completed"
    assert download.report.archived is True
    mapped = map_all(connector, "export_findings", download.records[:1], target=TARGET)
    assert mapped[0].unmapped["nessus"]["history_status"] == "completed"
    assert mapped[0].unmapped["nessus"]["archived"] is True


def test_live_export_with_unlisted_history_id_has_no_history_facts() -> None:
    connector = _connector()
    download = asyncio.run(connector.download_export(DownloadExportArgs(scan_id="1", file_id="77", history_id="99")))
    assert download.report.history_status is None
    assert download.report.archived is None


def test_history_lookup_pages_until_the_run_is_found() -> None:
    connector = _connector()
    full_page = {"history": [{"history_id": i, "status": "completed"} for i in range(1000, 1200)]}
    later = {"history": [{"history_id": 11, "status": "aborted", "is_archived": False}]}
    routes = RouteTransport(
        {
            ("GET", "/scans/1/history"): {"status": 200, "json": full_page},
            ("GET", "/scans/1/export/77/download"): {"status": 200, "text": (FIXTURES / "sample_scan.nessus").read_text()},
        }
    )
    connector.ctx.http._client._transport = routes
    original = connector.list_history
    offsets: list[int] = []

    async def paged(args: ListHistoryArgs) -> NessusHistoryList:
        offsets.append(args.offset)
        if args.offset == 0:
            return await original(args)
        return NessusHistoryList.model_validate(later)

    connector.list_history = paged  # type: ignore[method-assign]
    download = asyncio.run(connector.download_export(DownloadExportArgs(scan_id="1", file_id="77", history_id="11")))
    assert offsets == [0, 200]
    assert download.report.history_status == "aborted"
    assert download.report.archived is False


def test_upload_import_has_no_history_facts() -> None:
    connector = _connector()
    data = (FIXTURES / "sample_scan.nessus").read_bytes()
    report = connector._parse(
        data, scan_id=None, history_id=None, history_status=None, archived=None, source="upload"
    )
    assert report.report.history_status is None
    assert report.report.archived is None


@pytest.mark.parametrize("severity", ["1", "2", "3", "4"])
def test_identifier_free_severity_is_advisory_vulnerability(severity: str) -> None:
    connector = _connector()
    base = _advisory_report([(9001, severity)])
    records = connector._parse(
        base.encode(), scan_id="1", history_id=None, history_status=None, archived=None, source="live"
    ).records
    (advisory,) = map_all(connector, "export_findings", records, target=TARGET)
    assert isinstance(advisory, VulnerabilityFinding)
    assert advisory.class_uid == 2002
    vulnerability = advisory.vulnerabilities[0]
    assert vulnerability.advisory is not None
    assert vulnerability.advisory.uid == "nessus-plugin:9001"
    assert vulnerability.cve is None and vulnerability.cwe is None
    advisory.to_ocsf()


def test_identifier_free_informational_item_is_detection() -> None:
    connector = _connector()
    base = _advisory_report([(9002, "0")])
    records = connector._parse(
        base.encode(), scan_id="1", history_id=None, history_status=None, archived=None, source="live"
    ).records
    (detection,) = map_all(connector, "export_findings", records, target=TARGET)
    assert isinstance(detection, DetectionFinding)
    assert detection.class_uid == 2004
    assert detection.unmapped["nessus"]["plugin_id"] == "9002"


def test_advisory_uid_is_stable_across_reexport() -> None:
    connector = _connector()
    base = _advisory_report([(9001, "2")])
    first = connector._parse(
        base.encode(), scan_id="1", history_id=None, history_status=None, archived=None, source="live"
    ).records
    second = connector._parse(
        (base + "\n").encode(), scan_id="1", history_id=None, history_status=None, archived=None, source="live"
    ).records
    first_mapped = map_all(connector, "export_findings", first, target=TARGET)
    second_mapped = map_all(connector, "export_findings", second, target=TARGET)
    assert first_mapped[0].vulnerabilities[0].advisory.uid == second_mapped[0].vulnerabilities[0].advisory.uid


def test_compliance_check_uid_is_stable_across_reexport_and_keyed_by_identity() -> None:
    connector = _connector()
    base = (FIXTURES / "compliance_scan.nessus").read_text()
    first = connector._parse(
        base.encode(), scan_id="1", history_id=None, history_status=None, archived=None, source="live"
    ).records
    second = connector._parse(
        (base + "\n").encode(), scan_id="1", history_id=None, history_status=None, archived=None, source="live"
    ).records
    first_mapped = map_all(connector, "compliance_findings", first, target=TARGET)
    second_mapped = map_all(connector, "compliance_findings", second, target=TARGET)
    first_uids = [m.compliance.checks[0].uid for m in first_mapped]
    second_uids = [m.compliance.checks[0].uid for m in second_mapped]
    assert first_uids == second_uids
    for record, check_uid in zip(first, first_uids, strict=True):
        assert check_uid.startswith(f"{record.event_uid}:")


def test_compliance_checks_on_one_plugin_have_distinct_stable_finding_identity() -> None:
    connector = _connector()
    base = (FIXTURES / "compliance_scan.nessus").read_text().replace(
        'pluginID="3002"', 'pluginID="3001"'
    )
    first = connector._parse(
        base.encode(), scan_id="1", history_id=None, history_status=None, archived=None, source="live"
    ).records
    second = connector._parse(
        (base + "\n").encode(), scan_id="1", history_id=None, history_status=None, archived=None, source="live"
    ).records
    assert first[0].event_uid == first[1].event_uid

    mapped = map_all(connector, "compliance_findings", first, target=TARGET)
    remapped = map_all(connector, "compliance_findings", second, target=TARGET)
    finding_uids = [finding.finding_info.uid for finding in mapped]
    fingerprints = [finding.unmapped["icuhub"]["fingerprint"] for finding in mapped]
    assert len(set(finding_uids)) == 2
    assert len(set(fingerprints)) == 2
    assert all(re.fullmatch(r"fp_[0-9a-f]{64}", fingerprint) for fingerprint in fingerprints)
    assert finding_uids == [finding.finding_info.uid for finding in remapped]
    assert fingerprints == [finding.unmapped["icuhub"]["fingerprint"] for finding in remapped]


def test_download_export_passes_history_id_through() -> None:
    connector = _connector()
    download = asyncio.run(connector.download_export(DownloadExportArgs(scan_id="1", file_id="77", history_id="11")))
    assert download.report.history_id == "11"


def test_health_edition_gating() -> None:
    assert asyncio.run(_connector().check()).status == "healthy"
    report = asyncio.run(_connector(edition="Nessus Essentials").check())
    assert report.capabilities["export"].status == "not_evaluated"
    assert report.capabilities["FindingSource"].status == "not_evaluated"


def test_no_write_surface() -> None:
    assert not Nessus.actions()
    assert not Nessus.webhooks()
    assert Nessus.webhooks() == {}
