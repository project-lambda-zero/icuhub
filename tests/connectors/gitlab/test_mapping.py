"""Tests for the GitLab native finding to OCSF vulnerability mapping."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors._gitlab.mapping import NoIdentifierError, map_native_finding, map_native_findings
from icuhub.kit.errors import VendorContractError
from icuhub.kit.types import MapContext
from icuhub_schemas.ocsf import VulnerabilityFinding

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "gitlab"
RECEIVED_AT = datetime(2026, 11, 10, tzinfo=UTC)
RAW_MAX_BYTES = 32 * 1024


def _ctx() -> MapContext:
    return MapContext(
        connection_id="connection-1",
        tenant_id="tenant-1",
        connector_kind="gitlab",
        received_at=RECEIVED_AT,
    )


def _item(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": 7002,
        "uuid": "uuid-7002",
        "state": "confirmed",
        "report_type": "sast",
        "severity": "High",
        "name": "Out-of-bounds read",
        "description": "Parser reads past the end of the buffer.",
        "identifiers": [
            {"type": "cve", "value": "CVE-2024-12345"},
            {"type": "cwe", "value": "787"},
        ],
        "location": {"file": "src/parser/read.c", "start_line": 14, "end_line": 16},
    }
    item.update(overrides)
    return item


def test_complete_fixture_without_identifiers_drops_its_finding() -> None:
    payload = json.loads((FIXTURES / "native_findings_complete.json").read_text())

    result = map_native_findings(payload, _ctx())

    assert result.data == []
    assert result.coverage == "complete"
    assert result.dropped == [{"id": 7001, "reason": "no CVE or CWE identifier"}]


def test_incomplete_page_is_partial_and_keeps_identified_findings() -> None:
    payload = {"complete": False, "items": [_item(), _item(id=7003, uuid="uuid-7003", identifiers=[])]}

    result = map_native_findings(payload, _ctx())

    assert [finding.finding_info.uid for finding in result.data] == ["uuid-7002"]
    assert result.coverage == "partial"
    assert result.dropped == [{"id": 7003, "reason": "no CVE or CWE identifier"}]


def test_cve_finding_maps_to_ocsf_vulnerability_finding() -> None:
    finding = map_native_finding(_item(), _ctx())

    assert isinstance(finding, VulnerabilityFinding)
    assert finding.class_uid == 2002
    assert finding.type_uid == 200201
    assert finding.activity_id == 1
    assert finding.time == int(RECEIVED_AT.timestamp() * 1000)
    assert finding.severity_id == 4
    assert finding.severity == "High"
    assert finding.status_id == 2
    assert finding.status == "confirmed"
    assert finding.finding_info.uid == "uuid-7002"
    assert finding.finding_info.uid_alt == "7002"
    assert finding.finding_info.title == "Out-of-bounds read"
    assert finding.finding_info.desc == "Parser reads past the end of the buffer."
    assert finding.metadata.product.name == "GitLab"
    assert finding.metadata.product.vendor_name == "GitLab Inc."
    assert finding.cloud.provider == "gitlab"
    assert finding.osint == []


def test_cve_finding_nests_its_cwe_and_records_file_location() -> None:
    finding = map_native_finding(_item(), _ctx())

    vulnerability = finding.vulnerabilities[0]
    assert vulnerability.cwe is None
    assert vulnerability.cve is not None
    assert vulnerability.cve.uid == "CVE-2024-12345"
    assert vulnerability.cve.cwe is not None
    assert vulnerability.cve.cwe.uid == "CWE-787"
    assert vulnerability.category == "sast"
    assert vulnerability.affected_code is not None
    affected = vulnerability.affected_code[0]
    assert affected.file.name == "read.c"
    assert affected.file.path == "src/parser/read.c"
    assert affected.start_line == 14
    assert affected.end_line == 16


def test_cwe_only_finding_maps_to_cwe_vulnerability() -> None:
    finding = map_native_finding(_item(identifiers=[{"type": "cwe", "value": "79"}]), _ctx())

    vulnerability = finding.vulnerabilities[0]
    assert vulnerability.cve is None
    assert vulnerability.cwe is not None
    assert vulnerability.cwe.uid == "CWE-79"


def test_native_record_is_kept_under_unmapped_gitlab() -> None:
    finding = map_native_finding(_item(), _ctx())

    assert finding.unmapped is not None
    gitlab = finding.unmapped["gitlab"]
    assert gitlab["id"] == 7002
    assert gitlab["report_type"] == "sast"
    assert gitlab["state"] == "confirmed"
    assert gitlab["identifiers"] == [
        {"type": "cve", "value": "CVE-2024-12345"},
        {"type": "cwe", "value": "787"},
    ]


@pytest.mark.parametrize(
    ("state", "expected_id"),
    [("detected", 1), ("confirmed", 2), ("dismissed", 3), ("resolved", 4), ("unexpected", 0)],
)
def test_state_maps_to_ocsf_status_id(state: str, expected_id: int) -> None:
    finding = map_native_finding(_item(state=state), _ctx())

    assert finding.status_id == expected_id
    assert finding.status == state


def test_missing_severity_label_maps_to_unknown_severity() -> None:
    finding = map_native_finding(_item(severity=None), _ctx())

    assert finding.severity_id == 0
    assert finding.severity is None


def test_finding_without_identifiers_raises_no_identifier_error() -> None:
    with pytest.raises(NoIdentifierError) as excinfo:
        map_native_finding(_item(identifiers=[]), _ctx())

    assert excinfo.value.native_id == 7002


def test_large_record_is_bounded_to_raw_max_bytes_with_truncation_marker() -> None:
    finding = map_native_finding(_item(description="x" * 40_000), _ctx())

    assert finding.raw_data is not None
    assert len(finding.raw_data.encode("utf-8")) <= RAW_MAX_BYTES
    assert finding.raw_data.endswith("...[truncated]")


def test_multibyte_record_is_bounded_in_bytes_not_characters() -> None:
    finding = map_native_finding(_item(description="\u00e9" * 20_000), _ctx())

    assert finding.raw_data is not None
    assert len(finding.raw_data.encode("utf-8")) <= RAW_MAX_BYTES
    assert finding.raw_data.endswith("...[truncated]")


def test_small_record_is_kept_verbatim_in_raw_data() -> None:
    finding = map_native_finding(_item(), _ctx())

    assert finding.raw_data is not None
    assert json.loads(finding.raw_data)["uuid"] == "uuid-7002"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"id": 0}, "id must be a positive integer"),
        ({"uuid": ""}, "uuid must be a non-empty string"),
        ({"state": 3}, "state must be a string when present"),
        ({"identifiers": "CVE-2024-12345"}, "identifiers must be a list"),
        ({"identifiers": [{"type": "cwe", "value": "abc"}]}, "not numeric"),
        ({"identifiers": [{"type": "cve", "value": "2024-12345"}]}, "malformed"),
        ({"location": {"start_line": 3}}, "location.file must be a non-empty string"),
    ],
)
def test_malformed_finding_raises_vendor_contract_error(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(VendorContractError, match=message):
        map_native_finding(_item(**overrides), _ctx())


def test_malformed_page_raises_vendor_contract_error() -> None:
    with pytest.raises(VendorContractError):
        map_native_findings({"complete": "yes", "items": []}, _ctx())


@pytest.mark.parametrize(
    ("edition", "native_id"),
    [("gitlab", 7001), ("gitlab_self_managed", 8801)],
)
def test_both_editions_complete_fixture_drops_identifier_less_finding(edition: str, native_id: int) -> None:
    payload = json.loads((FIXTURES.parent / edition / "native_findings_complete.json").read_text())

    result = map_native_findings(payload, _ctx())

    assert result.data == []
    assert result.coverage == "complete"
    assert result.dropped == [{"id": native_id, "reason": "no CVE or CWE identifier"}]


@pytest.mark.parametrize("edition", ["gitlab", "gitlab_self_managed"])
def test_both_editions_incomplete_fixture_is_partial_and_empty(edition: str) -> None:
    payload = json.loads((FIXTURES.parent / edition / "native_findings_incomplete.json").read_text())

    result = map_native_findings(payload, _ctx())

    assert result.data == []
    assert result.coverage == "partial"
    assert result.dropped == []
