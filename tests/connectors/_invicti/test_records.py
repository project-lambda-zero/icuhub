"""Normalized Invicti record parsing tests."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC
from typing import Any

import pytest

from icuhub.connectors._invicti import (
    InvictiIssue,
    InvictiReport,
    InvictiScan,
    InvictiScanResult,
    parse_issue,
    parse_scan,
    parse_scan_result,
)
from icuhub.kit.errors import VendorContractError

from .conftest import load_fixture


def test_enterprise_issue_parses_all_typed_fields(enterprise_issue_raw: dict[str, Any]) -> None:
    issue = parse_issue(enterprise_issue_raw)

    assert isinstance(issue, InvictiIssue)
    assert issue.id == "6dc7a92f-94ab-4f7c-b60f-000000000301"
    assert issue.title == "SQL Injection"
    assert issue.severity == "High"
    assert issue.state == "Present"
    assert issue.confirmed is True
    assert issue.accepted_risk is False
    assert issue.false_positive is False
    assert issue.certainty == 100
    assert issue.location.url == "https://shop.example.test/products?q=1"
    assert issue.location.parameter == "q"
    assert issue.location.parameter_type == "GET"
    assert issue.website.id == "6dc7a92f-94ab-4f7c-b60f-000000000101"
    assert issue.website.name == "Shop"
    assert issue.website.root_url == "https://shop.example.test/"
    assert issue.proof.proof_of_concept == "' OR 1=1 --"
    assert issue.classification.cwe == "89"
    assert issue.classification.owasp_top_ten_2021 == "A03"
    assert issue.classification.pci_dss_40 == "6.2.4"
    assert issue.last_seen.tzinfo == UTC
    assert issue.last_seen.isoformat() == "2026-11-01T11:00:00+00:00"
    assert InvictiIssue.model_config["extra"] == "forbid"


def test_report_issue_uses_direct_proof_and_classification_fields(standard_issue_raw: dict[str, Any]) -> None:
    issue = parse_issue(standard_issue_raw)

    assert issue.id == "standard-issue-001"
    assert issue.title == "Cross-site Scripting"
    assert issue.confirmed is False
    assert issue.accepted_risk is False
    assert issue.false_positive is False
    assert issue.proof.attack_detail == "\"><script>alert(1)</script>"
    assert issue.proof.proof_of_concept == "Reflected in the search response."
    assert issue.classification.cwe == "79"
    assert issue.classification.cve == "CVE-2026-10002"
    assert issue.compliance.pci_dss_40 == "6.2.4"


@pytest.mark.parametrize(
    ("state", "accepted_risk", "false_positive"),
    [("AcceptedRisk", True, False), ("FalsePositive", False, True), ("Default", False, False)],
)
def test_state_derives_only_explicit_exception_flags(
    enterprise_issue_raw: dict[str, Any], state: str, accepted_risk: bool, false_positive: bool
) -> None:
    raw = deepcopy(enterprise_issue_raw)
    raw["State"] = state

    issue = parse_issue(raw)

    assert issue.state == state
    assert issue.accepted_risk is accepted_risk
    assert issue.false_positive is false_positive


def test_explicit_exception_flags_preserve_non_matching_source_state(enterprise_issue_raw: dict[str, Any]) -> None:
    raw = deepcopy(enterprise_issue_raw)
    raw["State"] = "Retest"
    raw["AcceptedRisk"] = True
    raw["FalsePositive"] = True

    issue = parse_issue(raw)

    assert issue.state == "Retest"
    assert issue.accepted_risk is True
    assert issue.false_positive is True


def test_scan_parses_native_execution_fields() -> None:
    raw = load_fixture("invicti_enterprise", "scans.json")["List"][0]

    scan = parse_scan(raw)

    assert isinstance(scan, InvictiScan)
    assert scan.id == "6dc7a92f-94ab-4f7c-b60f-000000000401"
    assert scan.website.id == "6dc7a92f-94ab-4f7c-b60f-000000000101"
    assert scan.state == "Complete"
    assert scan.completed is True
    assert scan.initiated.isoformat() == "2026-11-01T10:00:00+00:00"
    assert scan.state_changed.isoformat() == "2026-11-01T11:00:00+00:00"
    assert scan.total_vulnerability_count == 1
    assert InvictiScan.model_config["extra"] == "forbid"


def test_scan_result_wraps_normalized_issue() -> None:
    raw = load_fixture("invicti_enterprise", "scan_results.json")[0]

    result = parse_scan_result(raw, scan_id="scan-1")

    assert isinstance(result, InvictiScanResult)
    assert result.scan_id == "scan-1"
    assert result.issue_url.startswith("https://www.netsparkercloud.com/issues/")
    assert result.issue.id == raw["ExternalId"]
    assert result.issue.location.parameter == "q"
    assert result.issue.confirmed is None
    assert InvictiScanResult.model_config["extra"] == "forbid"


@pytest.mark.parametrize("field", ["Id", "Title", "Url", "Severity", "State", "LastSeenDate"])
def test_missing_required_issue_field_raises_vendor_error(
    enterprise_issue_raw: dict[str, Any], field: str
) -> None:
    raw = deepcopy(enterprise_issue_raw)
    del raw[field]

    with pytest.raises(VendorContractError, match=field):
        parse_issue(raw)


def test_unknown_vendor_field_is_not_silently_dropped(enterprise_issue_raw: dict[str, Any]) -> None:
    raw = deepcopy(enterprise_issue_raw)
    raw["Unexpected"] = "value"

    with pytest.raises(VendorContractError, match="Unexpected"):
        parse_issue(raw)


def test_invalid_timestamp_raises_vendor_error(enterprise_issue_raw: dict[str, Any]) -> None:
    raw = deepcopy(enterprise_issue_raw)
    raw["LastSeenDate"] = "not-a-date"

    with pytest.raises(VendorContractError, match="LastSeenDate"):
        parse_issue(raw)


def test_record_models_reject_unknown_normalized_fields() -> None:
    with pytest.raises(ValueError):
        InvictiReport(
            report_id="report-1",
            scan_id="scan-1",
            target_url="https://example.test/",
            scan_date="2026-11-01T00:00:00Z",
            vulnerabilities=[],
            file_sha256="a" * 64,
            parser_version="parser-1",
            unexpected=True,
        )
