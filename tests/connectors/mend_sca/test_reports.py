"""Offline Mend SCA report parser: schema detection, identity, bounds, and rejection (no network)."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors.mend_sca.models import MendSCAConfig
from icuhub.connectors.mend_sca.reports import parse_report
from icuhub.kit.errors import VendorContractError

from .conftest import BASE_CONFIG

FIXTURES = Path(__file__).parents[2] / "fixtures" / "mend_sca" / "report"
SNAPSHOT = "example-snapshot-one"


def _config(**overrides: Any) -> MendSCAConfig:
    return MendSCAConfig.model_validate({**BASE_CONFIG, **overrides})


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


@pytest.mark.parametrize(
    ("fixture", "schema"),
    [
        ("unified_agent_libraries.json", "unified_agent_libraries"),
        ("manual_vulnerabilities.json", "manual_vulnerabilities"),
        ("platform_components.json", "platform_components"),
        ("platform_3_response.json", "platform_3_response"),
    ],
)
def test_each_report_shape_is_detected_and_yields_records(fixture: str, schema: str) -> None:
    parsed = parse_report(_load(fixture), config=_config(), project_snapshot=SNAPSHOT)

    assert parsed.identity.report_schema == schema
    assert parsed.records, f"{fixture} produced no records"
    assert parsed.identity.project_snapshot == SNAPSHOT


def test_report_identity_is_the_sha256_of_the_exact_bytes() -> None:
    data = _load("unified_agent_libraries.json")

    parsed = parse_report(data, config=_config(), project_snapshot=SNAPSHOT)

    assert parsed.identity.report_sha256 == hashlib.sha256(data).hexdigest()
    assert parsed.identity.snapshot_id == parsed.identity.report_sha256


def test_same_bytes_parse_to_identical_records() -> None:
    data = _load("manual_vulnerabilities.json")

    first = parse_report(data, config=_config(), project_snapshot=SNAPSHOT)
    second = parse_report(data, config=_config(), project_snapshot=SNAPSHOT)

    assert first.records == second.records
    assert first.identity == second.identity


def test_record_keys_are_schema_scoped_identities() -> None:
    parsed = parse_report(_load("unified_agent_libraries.json"), config=_config(), project_snapshot=SNAPSHOT)

    for record in parsed.records:
        assert record["key"].startswith("unified_agent_libraries:")


def test_identity_less_rows_are_skipped_and_reported_incomplete() -> None:
    document = {"libraries": [{"name": None, "version": "1.0.0", "vulnerabilities": [{"name": None}]}]}

    parsed = parse_report(json.dumps(document).encode(), config=_config(), project_snapshot=SNAPSHOT)

    assert parsed.records == []
    assert parsed.identity.complete is False
    assert "skipped_record_missing_identity" in parsed.identity.incomplete_reasons


def test_oversized_report_is_rejected() -> None:
    # Trailing JSON whitespace keeps the document valid and pushes it past the 1024-byte minimum bound.
    data = _load("unified_agent_libraries.json") + b" " * 1024
    assert len(data) > 1024

    with pytest.raises(VendorContractError, match="max_report_bytes"):
        parse_report(data, config=_config(max_report_bytes=1024), project_snapshot=SNAPSHOT)


def test_over_deep_report_is_rejected() -> None:
    nested: Any = "leaf"
    for _ in range(80):
        nested = {"n": nested}
    data = json.dumps({"libraries": [nested]}).encode()

    with pytest.raises(VendorContractError, match="max_report_depth"):
        parse_report(data, config=_config(max_report_depth=8), project_snapshot=SNAPSHOT)


def test_over_long_string_is_rejected() -> None:
    data = json.dumps({"libraries": [{"name": "x" * 500}]}).encode()

    with pytest.raises(VendorContractError, match="max_report_string_chars"):
        parse_report(data, config=_config(max_report_string_chars=128), project_snapshot=SNAPSHOT)


def test_unknown_document_shape_is_rejected() -> None:
    with pytest.raises(VendorContractError, match="exactly one of"):
        parse_report(_load("direct_v2_retval.json"), config=_config(), project_snapshot=SNAPSHOT)


def _platform_report(*findings: dict[str, Any]) -> bytes:
    rows = [
        {
            "name": f"CVE-2099-000{index}",
            "findingInfo": {"uuid": f"finding-{index}", **info},
            "component": {"name": "example-library-2.4.1", "groupId": "com.example", "artifactId": "example-library", "version": "2.4.1", "path": "com.example:example-library:2.4.1"},
            "vulnerability": {"name": f"CVE-2099-000{index}", "severity": "HIGH"},
        }
        for index, info in enumerate(findings, start=1)
    ]
    return json.dumps({"response": rows}).encode()


@pytest.mark.parametrize(
    ("finding_status", "status", "suppressed", "reason"),
    [
        ("UNREVIEWED", "ACTIVE", False, None),
        ("IN_REVIEW", "ACTIVE", False, None),
        ("ISSUE_CREATED", "ACTIVE", False, None),
        ("REMEDIATED", "ACTIVE", False, None),
        ("SUPPRESSED", "ACTIVE", True, "SUPPRESSED"),
        ("UNREVIEWED", "IGNORED", True, "IGNORED"),
    ],
)
def test_report_suppression_is_limited_to_suppressed_and_ignored(
    finding_status: str, status: str, suppressed: bool, reason: str | None
) -> None:
    data = _platform_report({"findingStatus": finding_status, "status": status})

    parsed = parse_report(data, config=_config(), project_snapshot=SNAPSHOT)

    [record] = parsed.records
    assert record["fields"]["suppressed"] is suppressed
    assert record["fields"]["suppression_reason"] == reason


def test_report_unreviewed_row_is_kept_and_not_suppressed() -> None:
    data = _platform_report({"findingStatus": "UNREVIEWED", "status": "ACTIVE"})

    parsed = parse_report(data, config=_config(), project_snapshot=SNAPSHOT)

    assert len(parsed.records) == 1
    assert parsed.records[0]["fields"]["suppressed"] is False


def test_platform_3_fixture_suppressed_row_carries_vendor_reason() -> None:
    parsed = parse_report(_load("platform_3_response.json"), config=_config(), project_snapshot=SNAPSHOT)

    suppressed = [record for record in parsed.records if record["fields"]["suppressed"]]
    assert len(suppressed) == 1
    assert suppressed[0]["fields"]["suppression_reason"] == "SUPPRESSED"
    others = [record for record in parsed.records if not record["fields"]["suppressed"]]
    assert others
    assert all(record["fields"]["suppression_reason"] is None for record in others)


def test_non_json_report_is_rejected() -> None:
    with pytest.raises(VendorContractError, match="not UTF-8 JSON"):
        parse_report(b"\xff\xfe not json", config=_config(), project_snapshot=SNAPSHOT)
