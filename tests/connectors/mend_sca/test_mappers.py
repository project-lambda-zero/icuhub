"""Mend SCA pure mappers: vendor records to OCSF findings and source records (offline)."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors.mend_sca.mappers import (
    map_activity,
    map_legal_alert,
    map_library,
    map_project,
    map_report_finding,
    map_security_alert,
    map_security_finding,
)
from icuhub.kit.errors import VendorContractError
from icuhub.kit.types import MapContext

from .conftest import ORG_UUID

FIXTURES = Path(__file__).parents[2] / "fixtures" / "mend_sca"
FINDING_UUID = "00000000-0000-4000-8000-000000000401"
PROJECT_UUID = "00000000-0000-4000-8000-000000000101"
LIBRARY_UUID = "00000000-0000-4000-8000-000000000301"
ACTIVITY_UUID = "00000000-0000-4000-8000-000000000801"
RECEIVED_AT = datetime(2026, 1, 20, tzinfo=UTC)


def _ctx(received_at: datetime = RECEIVED_AT) -> MapContext:
    return MapContext(
        connection_id="conn-mend",
        tenant_id="tenant-test",
        connector_kind="mend_sca",
        target=None,
        received_at=received_at,
    )


def _fixture(*parts: str) -> Any:
    return json.loads((FIXTURES.joinpath(*parts)).read_text(encoding="utf-8"))


def _org(record: dict[str, Any]) -> dict[str, Any]:
    """Attach the connector-injected organization key every mapper requires."""
    return {**record, "_organization": ORG_UUID}


def _first(page: dict[str, Any], key: str) -> dict[str, Any]:
    return _org(page[key][0])


def test_security_finding_maps_to_active_ocsf_finding() -> None:
    page = _fixture("v3", "security_findings_page1.json")
    [finding] = map_security_finding(_first(page, "response"), _ctx())

    assert finding.finding_info.uid.startswith(f"mend_sca:{ORG_UUID}:")
    assert FINDING_UUID in finding.finding_info.uid
    assert finding.status == "ACTIVE"
    assert finding.status_id == 1
    assert finding.vulnerabilities[0].cve.uid == "CVE-2099-0001"
    assert finding.vulnerabilities[0].affected_packages[0].name == "example-library-2.4.1"


def test_security_finding_fingerprint_ignores_volatile_status_fields() -> None:
    page = _fixture("v3", "security_findings_page1.json")
    record = _first(page, "response")
    moved = {
        **record,
        "findingInfo": {
            **record["findingInfo"],
            "findingStatus": "SUPPRESSED",
            "modifiedAt": "2026-02-01T00:00:00Z",
            "comment": "triaged",
        },
    }

    [before] = map_security_finding(record, _ctx())
    [after] = map_security_finding(moved, _ctx())

    assert before.finding_info.uid_alt is not None
    assert after.finding_info.uid_alt == before.finding_info.uid_alt
    assert after.status_id == 3
    assert after.status == "SUPPRESSED"


@pytest.mark.parametrize(
    ("finding_status", "status_id"),
    [
        ("UNREVIEWED", 1),
        ("IN_REVIEW", 2),
        ("ISSUE_CREATED", 2),
        ("SUPPRESSED", 3),
        ("REMEDIATED", 4),
    ],
)
def test_security_finding_status_enum_maps_to_ocsf(finding_status: str, status_id: int) -> None:
    page = _fixture("v3", "security_findings_page1.json")
    record = _first(page, "response")
    record = {**record, "findingInfo": {**record["findingInfo"], "findingStatus": finding_status}}

    [finding] = map_security_finding(record, _ctx())

    assert finding.status == finding_status
    assert finding.status_id == status_id


@pytest.mark.parametrize("info_status", ["LIBRARY_IN_HOUSE", "LIBRARY_WHITELIST", "NOT_A_VENDOR_VALUE"])
def test_unmapped_finding_status_is_unknown_not_terminal(info_status: str) -> None:
    page = _fixture("v3", "security_findings_page1.json")
    record = _first(page, "response")
    record = {**record, "findingInfo": {**record["findingInfo"], "findingStatus": info_status}}

    [finding] = map_security_finding(record, _ctx())

    assert finding.status_id == 0


@pytest.mark.parametrize(
    ("reachability", "expected"),
    [
        ("REACHABLE", "REACHABLE"),
        ("POTENTIALLY_REACHABLE", "POTENTIALLY_REACHABLE"),
        ("UNREACHABLE", "UNREACHABLE"),
        ("REACHABILITY_UNAVAILABLE", "REACHABILITY_UNAVAILABLE"),
        ("SOMETHING_NEW", None),
    ],
)
def test_security_finding_reachability_passes_enum_values_only(reachability: str, expected: str | None) -> None:
    page = _fixture("v3", "security_findings_page1.json")
    record = _first(page, "response")
    record = {**record, "reachability": reachability, "exploitable": True, "malicious": False}

    [finding] = map_security_finding(record, _ctx())

    mend = finding.unmapped["mend_sca"]
    assert mend.get("reachability") == expected
    assert mend["exploitable"] is True
    assert mend["malicious"] is False


def test_security_finding_top_fix_is_read_from_finding_record() -> None:
    page = _fixture("v3", "security_findings_page1.json")
    record = _first(page, "response")
    top_fix = {
        "id": 49422,
        "vulnerability": "CVE-2022-4245",
        "type": "UPGRADE_VERSION",
        "origin": "WHITESOURCE_EXPERT",
        "url": "https://github.com/codehaus-plexus/plexus-utils/commit/f933e5e78dc2637e485447ed821fe14904f110de",
        "fixResolution": "3.0.24",
        "date": "2022-12-01T00:00:00Z",
        "message": "Upgrade to version",
    }
    record = {**record, "topFix": top_fix}

    [finding] = map_security_finding(record, _ctx())

    preserved = finding.unmapped["mend_sca"]["top_fix"]
    assert preserved["id"] == "49422"
    assert preserved["type"] == "UPGRADE_VERSION"
    assert preserved["origin"] == "WHITESOURCE_EXPERT"
    assert preserved["fix_resolution"] == "3.0.24"
    assert preserved["url"] == top_fix["url"]
    assert preserved["message"] == "Upgrade to version"


def test_security_finding_without_organization_is_rejected() -> None:
    page = _fixture("v3", "security_findings_page1.json")
    with pytest.raises(VendorContractError, match="_organization"):
        map_security_finding(page["response"][0], _ctx())


def test_security_alert_preserves_ignored_vendor_status() -> None:
    page = _fixture("v2", "security_alerts_page1.json")
    [finding] = map_security_alert(_org(page["retVal"][1]), _ctx())

    assert finding.status == "IGNORED"
    assert finding.status_id == 3
    assert finding.vulnerabilities[0].cve.uid == "CVE-2099-0001"


def test_legal_alert_open_violation_is_check_fail() -> None:
    page = _fixture("v2", "legal_alerts_page1.json")
    [finding] = map_legal_alert(_org(page["retVal"][0]), _ctx())

    assert finding.status == "ACTIVE"
    assert finding.status_id == 1
    assert finding.compliance.status_id == 2


def _report_row(report_sha: str, **fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "vulnerability_id": "CVE-2099-0001",
        "suppressed": False,
        "library_name": "example-library",
        "library_version": "2.4.1",
        "library_purl": "pkg:maven/com.example/example-library@2.4.1",
        "project_name": "example-project-one",
        "dependency_path": ["example-application", "example-library"],
    }
    return {
        "schema": "unified_agent_libraries",
        "key": "row-1",
        "fields": {**base, **fields},
        "_organization": ORG_UUID,
        "_report_sha256": report_sha,
    }


def test_report_suppressed_row_keeps_vendor_status() -> None:
    [finding] = map_report_finding(_report_row("a" * 64, suppressed=True, suppression_reason="IGNORED"), _ctx())

    assert finding.status == "IGNORED"
    assert finding.status_id == 3


def test_report_active_row_is_active() -> None:
    [finding] = map_report_finding(_report_row("a" * 64), _ctx())

    assert finding.status == "ACTIVE"
    assert finding.status_id == 1


def test_report_uid_is_keyed_by_report_but_fingerprint_is_shared() -> None:
    [first] = map_report_finding(_report_row("a" * 64), _ctx())
    [second] = map_report_finding(_report_row("b" * 64), _ctx())

    assert first.finding_info.uid != second.finding_info.uid
    assert first.finding_info.uid_alt == second.finding_info.uid_alt


def test_report_non_boolean_suppressed_is_rejected() -> None:
    with pytest.raises(VendorContractError, match="suppressed"):
        map_report_finding(_report_row("a" * 64, suppressed="yes"), _ctx())


def test_library_maps_to_inventory_record_keyed_by_project_and_library() -> None:
    page = _fixture("v3", "libraries_page1.json")
    [record] = map_library(_first(page, "response"), _ctx())

    assert record.record_type == "library"
    assert record.uid == f"mend_sca:{ORG_UUID}:library:{PROJECT_UUID}:{LIBRARY_UUID}"
    assert record.revision == "2.4.1"
    assert record.data["name"] == "example-library-2.4.1"
    assert record.data["project_uuid"] == PROJECT_UUID


def test_activity_maps_to_audit_event_with_scope_asset() -> None:
    page = _fixture("v3", "activity_page1.json")
    [record] = map_activity(_first(page, "response"), _ctx())

    expected_ms = int(datetime(2026, 1, 16, 9, 30, tzinfo=UTC).timestamp() * 1000)
    assert record.record_type == "audit_event"
    assert record.uid == f"mend_sca:{ORG_UUID}:activity:{ACTIVITY_UUID}"
    assert record.data["event_type"] == "PROJECT_SCANNED"
    assert record.data["occurred_at"] == expected_ms
    assert record.data["actor"] == "example-user"
    assert record.data["asset_ref"] == f"project:{ORG_UUID}/{PROJECT_UUID}"


def test_activity_without_timestamp_is_rejected() -> None:
    page = _fixture("v3", "activity_page1.json")
    record = {k: v for k, v in _first(page, "response").items() if k != "timestamp"}
    with pytest.raises(VendorContractError, match="timestamp"):
        map_activity(record, _ctx())


def _project(**overrides: Any) -> dict[str, Any]:
    page = _fixture("v3", "projects_page1.json")
    return {**_first(page, "response"), "_stale_after_days": 30, **overrides}


def test_project_with_recent_complete_rollup_is_current_and_complete() -> None:
    [record] = map_project(_project(), _ctx())

    assert record.record_type == "project"
    assert record.data["scan_state"] == "current"
    assert record.data["coverage"] == "complete"
    assert record.data["rollup"]["findings"]["total"] == 2
    assert record.data["zero_findings"] is False


def test_project_past_stale_window_is_partial_with_rollup_retained() -> None:
    [record] = map_project(_project(), _ctx(datetime(2026, 3, 1, tzinfo=UTC)))

    assert record.data["scan_state"] == "stale"
    assert record.data["coverage"] == "partial"
    assert record.data["rollup"] is not None
    assert record.data["zero_findings"] is None


def test_project_never_scanned_is_not_evaluated() -> None:
    project = _project()
    del project["lastScanDate"]
    [record] = map_project(project, _ctx())

    assert record.data["scan_state"] == "never_scanned"
    assert record.data["coverage"] == "not_evaluated"
    assert record.data["rollup"] is None


def test_denied_project_is_not_evaluated_and_carries_no_rollup() -> None:
    project = _project(_access="denied")
    [record] = map_project(project, _ctx())

    assert record.data["scan_state"] == "denied"
    assert record.data["coverage"] == "not_evaluated"
    assert record.data["rollup"] is None


def test_project_without_stale_window_is_rejected() -> None:
    project = _project()
    del project["_stale_after_days"]
    with pytest.raises(VendorContractError, match="_stale_after_days"):
        map_project(project, _ctx())
