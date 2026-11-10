"""Archer mapper tests: OCSF findings, stable fingerprints, SourceRecord output."""

from typing import Any

from icuhub.kit import SourceRecord
from icuhub.kit.testing import map_all
from icuhub_schemas.ocsf import ComplianceFinding, VulnerabilityFinding

from .conftest import RouteTransport, make_archer


def connector():
    return make_archer(RouteTransport({}))


def scan_raw(**field_overrides):
    fields = {
        "Title": "CVE-2026-0001",
        "Description": "Example vulnerability",
        "Severity": "High",
        "Status": "Open",
        "CVE": "CVE-2026-0001",
        "Device": "host1.example.test",
        "Port": "443",
        "LastUpdated": "2026-01-02T03:04:05Z",
    }
    fields.update(field_overrides)
    return {
        "content_id": 1001,
        "level_id": 401,
        "application_id": 301,
        "record_type": "vulnerability_scan_results",
        "fields": fields,
    }


def test_vulnerability_finding_fields():
    out = map_all(connector(), "vulnerability_scan_results", [scan_raw()])
    assert len(out) == 1
    finding = out[0]
    assert isinstance(finding, VulnerabilityFinding)
    assert finding.class_uid == 2002
    assert finding.type_uid == 200201
    assert finding.activity_id == 1
    assert finding.time == 1767323045000
    assert finding.severity_id == 4
    assert finding.metadata.product.name == "Archer GRC"
    assert finding.cloud.provider == "archer"
    assert finding.osint == []
    assert finding.status == "Open"
    assert finding.finding_info.title == "CVE-2026-0001"
    assert finding.finding_info.uid_alt == "1001"
    cve = finding.vulnerabilities[0].cve
    assert cve is not None and cve.uid == "CVE-2026-0001"
    resources = finding.resources
    assert resources is not None and resources[0].name == "host1.example.test"
    finding.to_ocsf()


def test_fingerprint_stable_and_selective():
    first: Any = map_all(connector(), "vulnerability_scan_results", [scan_raw()])[0]
    again: Any = map_all(connector(), "vulnerability_scan_results", [scan_raw()])[0]
    assert first.finding_info.uid == again.finding_info.uid
    changed_cosmetics: Any = map_all(
        connector(),
        "vulnerability_scan_results",
        [scan_raw(Severity="Low", Status="Closed", Version="99")],
    )[0]
    assert changed_cosmetics.finding_info.uid == first.finding_info.uid
    changed_cve: Any = map_all(connector(), "vulnerability_scan_results", [scan_raw(CVE="CVE-2026-0002")])[0]
    assert changed_cve.finding_info.uid != first.finding_info.uid
    changed_device: Any = map_all(
        connector(), "vulnerability_scan_results", [scan_raw(Device="host2.example.test")]
    )[0]
    assert changed_device.finding_info.uid != first.finding_info.uid
    changed_port: Any = map_all(connector(), "vulnerability_scan_results", [scan_raw(Port="8443")])[0]
    assert changed_port.finding_info.uid != first.finding_info.uid


def test_compliance_finding_fields():
    raw = {
        "content_id": 2001,
        "level_id": 402,
        "application_id": 302,
        "record_type": "assessment_findings",
        "fields": {
            "Title": "Control C-1",
            "Control": "C-1",
            "Status": "Fail",
            "Severity": "Medium",
            "Standard": "ISO 27001",
            "Description": "Control failed",
            "Remediation": "Apply the control",
            "LastUpdated": "2026-01-02T03:04:05Z",
        },
    }
    out = map_all(connector(), "assessment_findings", [raw])
    finding = out[0]
    assert isinstance(finding, ComplianceFinding)
    assert finding.class_uid == 2003
    assert finding.type_uid == 200301
    assert finding.severity_id == 3
    assert finding.compliance.control == "C-1"
    assert finding.compliance.status == "Fail"
    assert finding.compliance.standards == ["ISO 27001"]
    assert finding.remediation is not None
    assert finding.remediation.desc == "Apply the control"
    finding.to_ocsf()


def test_source_record_for_non_finding_streams():
    raw = {
        "content_id": 1001,
        "level_id": 401,
        "application_id": 301,
        "record_type": "risks",
        "fields": {"Title": "Risk A"},
    }
    out = map_all(connector(), "risks", [raw])
    record = out[0]
    assert isinstance(record, SourceRecord)
    assert record.record_type == "risks"
    assert record.uid == "archer:risks:1001"
    assert record.data["content_id"] == 1001
    assert "Risk A" in record.data["raw"]
    assert record.data["observed_at"]


def test_source_record_uids_for_snapshot_streams():
    attachment = {
        "record_type": "attachments",
        "content_id": 1001,
        "attachment_id": 77,
        "filename": "evidence.pdf",
        "fields": {},
    }
    out = map_all(connector(), "attachments", [attachment])
    assert isinstance(out[0], SourceRecord)
    assert out[0].uid == "archer:attachments:1001:77"
    run = {"record_type": "data_feed_runs", "run": {"Guid": "df-1"}, "run_index": 0}
    out = map_all(connector(), "data_feed_runs", [run])
    assert isinstance(out[0], SourceRecord)
    assert out[0].uid == "archer:data_feed_runs:df-1"
