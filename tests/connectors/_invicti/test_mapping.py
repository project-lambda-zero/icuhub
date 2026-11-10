"""Invicti to OCSF 2002 mapping tests."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors._invicti import (
    map_issue_to_finding,
    map_report_to_findings,
    map_scan_result_to_finding,
    parse_issue,
    parse_report,
    parse_scan_result,
)
from icuhub.kit.types import MapContext
from icuhub_schemas.ocsf import VulnerabilityFinding

from .conftest import load_fixture

_FIXTURES = Path(__file__).parents[2] / "fixtures"


def _invicti_fields(finding: VulnerabilityFinding) -> dict[str, Any]:
    assert finding.unmapped is not None
    return finding.unmapped["invicti"]


def test_enterprise_issue_maps_to_valid_ocsf_2002(
    enterprise_issue_raw: dict[str, Any], map_context: MapContext
) -> None:
    finding = map_issue_to_finding(parse_issue(enterprise_issue_raw), map_context)

    assert isinstance(finding, VulnerabilityFinding)
    assert finding.class_uid == 2002
    assert finding.type_uid == 200201
    assert finding.severity_id == 4
    assert finding.severity == "High"
    assert finding.status_id == 1
    assert finding.status == "New"
    assert finding.status_detail == "Present"
    assert finding.finding_info.uid == enterprise_issue_raw["Id"]
    assert finding.finding_info.first_seen_time is not None
    assert finding.finding_info.last_seen_time == 1793530800000
    assert finding.time == 1793530800000
    assert finding.vulnerabilities[0].cwe is not None
    assert finding.vulnerabilities[0].cwe.uid == "CWE-89"
    assert finding.resources is not None
    assert finding.resources[0].uid == (
        "web_application:connection-1/6dc7a92f-94ab-4f7c-b60f-000000000101"
    )
    finding.to_ocsf()


@pytest.mark.parametrize(
    ("vendor_label", "severity_id", "caption"),
    [
        ("Critical", 5, "Critical"),
        ("High", 4, "High"),
        ("Medium", 3, "Medium"),
        ("Low", 2, "Low"),
        ("Information", 1, "Informational"),
        ("BestPractice", 1, "Informational"),
        ("Unknown", 0, "Unknown"),
    ],
)
def test_all_native_severity_labels_map_to_ocsf_id_and_caption(
    enterprise_issue_raw: dict[str, Any],
    map_context: MapContext,
    vendor_label: str,
    severity_id: int,
    caption: str,
) -> None:
    raw = deepcopy(enterprise_issue_raw)
    raw["Severity"] = vendor_label

    finding = map_issue_to_finding(parse_issue(raw), map_context)

    assert finding.severity_id == severity_id
    assert finding.severity == caption
    assert _invicti_fields(finding)["raw_severity"] == vendor_label


def test_unrecognized_severity_is_unknown_and_text_is_preserved(
    enterprise_issue_raw: dict[str, Any], map_context: MapContext
) -> None:
    raw = deepcopy(enterprise_issue_raw)
    raw["Severity"] = "VendorFutureSeverity"

    finding = map_issue_to_finding(parse_issue(raw), map_context)

    assert finding.severity_id == 0
    assert finding.severity == "Unknown"
    assert _invicti_fields(finding)["raw_severity"] == "VendorFutureSeverity"


def test_typed_gap_fields_and_bounded_proof_are_present(
    map_context: MapContext,
) -> None:
    raw = load_fixture("invicti_standard", "report.json")["Vulnerabilities"][0]
    raw["AcceptedRisk"] = True
    raw["FalsePositive"] = True
    raw["State"] = "CustomVendorState"
    raw["AttackDetail"] = "<script>alert('token=html-secret')</script>"
    raw["HttpRequest"] = "GET /search?token=http-secret HTTP/1.1\r\nAuthorization: Bearer header-secret"
    raw["HttpResponse"] = "HTTP/1.1 200 OK\r\nSet-Cookie: session=response-secret"

    finding = map_issue_to_finding(parse_issue(raw), map_context)
    fields = _invicti_fields(finding)

    assert finding.status_id == 0
    assert finding.status == "Unknown"
    assert finding.status_detail == "CustomVendorState"
    assert fields["verification"] == {"confirmed": False, "certainty": 75}
    assert fields["accepted_risk"] is True
    assert fields["false_positive"] is True
    assert fields["classification"]["cwe"] == "79"
    assert fields["classification"]["owasp_top_ten_2021"] == "A03"
    assert fields["compliance"]["pci_dss_40"] == "6.2.4"
    assert fields["location"] == {
        "url": "https://blog.example.test/search?term=example",
        "parameter": "term",
        "parameter_type": None,
    }
    assert fields["proof"]["attack_detail"]["truncated"] is False
    assert fields["proof"]["attack_detail"]["redacted"] is True
    assert fields["proof"]["http_request"]["sha256"]
    assert fields["proof"]["http_response"]["sha256"]
    serialized = finding.model_dump(mode="json")
    for secret in ["html-secret", "http-secret", "header-secret", "response-secret"]:
        assert secret not in str(serialized)
    assert finding.vulnerabilities[0].cve is not None
    assert finding.vulnerabilities[0].cve.uid == "CVE-2026-10002"
    assert finding.vulnerabilities[0].cve.cwe is not None
    assert finding.vulnerabilities[0].cve.cwe.uid == "CWE-79"
    finding.to_ocsf()


def test_state_is_never_inferred_from_jira_like_fields(
    enterprise_issue_raw: dict[str, Any], map_context: MapContext
) -> None:
    raw = deepcopy(enterprise_issue_raw)
    raw["State"] = "FixedUnconfirmed"
    raw["JiraStatus"] = "Done"

    with pytest.raises(Exception, match="JiraStatus"):
        parse_issue(raw)

    del raw["JiraStatus"]
    finding = map_issue_to_finding(parse_issue(raw), map_context)

    assert finding.status_detail == "FixedUnconfirmed"
    assert finding.status == "In Progress"
    assert finding.status_id == 2


@pytest.mark.parametrize(
    ("state", "status_id", "caption"),
    [
        ("Present", 1, "New"),
        ("Revived", 1, "New"),
        ("FixedUnconfirmed", 2, "In Progress"),
        ("Ignored", 3, "Suppressed"),
        ("FalsePositive", 3, "Suppressed"),
        ("FixedConfirmed", 4, "Resolved"),
        ("AcceptedRisk", 0, "Unknown"),
        ("FixedCantRetest", 0, "Unknown"),
        ("Scanning", 0, "Unknown"),
        ("Retest", 0, "Unknown"),
        ("CustomVendorState", 0, "Unknown"),
    ],
)
def test_documented_states_map_to_ocsf_status_and_preserve_raw_state(
    enterprise_issue_raw: dict[str, Any],
    map_context: MapContext,
    state: str,
    status_id: int,
    caption: str,
) -> None:
    raw = deepcopy(enterprise_issue_raw)
    raw["State"] = state

    finding = map_issue_to_finding(parse_issue(raw), map_context)

    assert finding.status_id == status_id
    assert finding.status == caption
    assert finding.status_detail == state
    assert _invicti_fields(finding)["state"] == state


def test_scan_result_mapping_preserves_scan_identity(map_context: MapContext) -> None:
    raw = load_fixture("invicti_enterprise", "scan_results.json")[0]
    result = parse_scan_result(raw, scan_id="scan-1", website_id="website-1")

    finding = map_scan_result_to_finding(result, map_context)
    fields = _invicti_fields(finding)

    assert fields["scan_id"] == "scan-1"
    assert fields["website"]["id"] == "website-1"
    assert finding.metadata.uid == "scan-1"
    finding.to_ocsf()


def test_report_mapping_links_each_finding_to_report_snapshot(map_context: MapContext) -> None:
    data = (_FIXTURES / "invicti_enterprise" / "report.json").read_bytes()
    report = parse_report(data)

    findings = map_report_to_findings(report, map_context)

    assert len(findings) == 1
    fields = _invicti_fields(findings[0])
    assert fields["report"]["report_id"] == report.report_id
    assert fields["report"]["file_sha256"] == report.file_sha256
    assert fields["report"]["snapshot_id"] == report.snapshot.snapshot_id
    assert fields["report"]["parser_version"] == report.parser_version
    assert findings[0].metadata.uid == report.snapshot.snapshot_id
    assert findings[0].proof if hasattr(findings[0], "proof") else True
    findings[0].to_ocsf()


def test_mapping_time_falls_back_to_observation_time_when_native_time_absent(
    enterprise_issue_raw: dict[str, Any], map_context: MapContext
) -> None:
    issue = parse_issue(enterprise_issue_raw).model_copy(update={"last_seen": None})

    finding = map_issue_to_finding(issue, map_context)

    assert finding.time == int(map_context.received_at.timestamp() * 1000)
    assert map_context.received_at.tzinfo == UTC
