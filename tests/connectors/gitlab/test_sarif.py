"""Tests for the GitLab SARIF publish build and parse."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors._gitlab.mapping import map_native_finding
from icuhub.connectors._gitlab.sarif import build_publish_sarif, parse_publish_sarif
from icuhub.kit.errors import VendorContractError
from icuhub.kit.types import MapContext
from icuhub_schemas.ocsf import VulnerabilityFinding
from icuhub_schemas.sarif import SarifValidationError, parse_sarif

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "gitlab"
VALID = FIXTURES / "sarif_report_valid.sarif.json"
WITH_DROP = FIXTURES / "sarif_report_with_drop.sarif.json"
MAX_BYTES = 10 * 1024 * 1024
MAX_RUNS = 20
MAX_RESULTS_PER_RUN = 5000


def _ctx() -> MapContext:
    return MapContext(
        connection_id="connection-1",
        tenant_id="tenant-1",
        connector_kind="gitlab",
        received_at=datetime(2026, 11, 10, tzinfo=UTC),
    )


def _finding(uuid: str, *, location: dict[str, Any] | None) -> VulnerabilityFinding:
    return map_native_finding(
        {
            "id": 8000 + len(uuid),
            "uuid": uuid,
            "state": "detected",
            "report_type": "sast",
            "severity": "High",
            "name": f"Finding {uuid}",
            "identifiers": [{"type": "cve", "value": "CVE-2024-12345"}],
            "location": location,
        },
        _ctx(),
    )


def _parse(data: bytes | str | dict[str, Any], **overrides: int) -> Any:
    limits: dict[str, int] = {
        "max_bytes": MAX_BYTES,
        "max_runs": MAX_RUNS,
        "max_results_per_run": MAX_RESULTS_PER_RUN,
    }
    limits.update(overrides)
    return parse_publish_sarif(data, **limits)


def test_built_document_carries_one_result_per_located_finding() -> None:
    findings = [
        _finding("uuid-a", location={"file": "src/a.c", "start_line": 3}),
        _finding("uuid-b", location={"file": "src/b.c", "start_line": 9, "end_line": 11}),
    ]

    result = build_publish_sarif(findings, tool_version="1.2.3", max_results=10)

    assert result.coverage == "complete"
    assert result.dropped == []
    driver = result.data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "ICUHUB GitLab"
    assert driver["version"] == "1.2.3"
    results = result.data["runs"][0]["results"]
    assert [entry["ruleId"] for entry in results] == ["CVE-2024-12345", "CVE-2024-12345"]
    assert [entry["message"]["text"] for entry in results] == ["Finding uuid-a", "Finding uuid-b"]
    locations = [entry["locations"][0]["physicalLocation"] for entry in results]
    assert locations[0]["artifactLocation"]["uri"] == "src/a.c"
    assert locations[1]["artifactLocation"]["uri"] == "src/b.c"
    parse_sarif(result.data)


def test_finding_without_code_location_is_dropped_and_coverage_is_partial() -> None:
    findings = [
        _finding("uuid-a", location={"file": "src/a.c", "start_line": 3}),
        _finding("uuid-none", location=None),
    ]

    result = build_publish_sarif(findings, tool_version=None, max_results=10)

    assert result.coverage == "partial"
    assert result.dropped == [{"uid": "uuid-none", "reason": "no code location"}]
    assert len(result.data["runs"][0]["results"]) == 1
    parse_sarif(result.data)


def test_empty_findings_build_a_valid_empty_document() -> None:
    result = build_publish_sarif([], tool_version=None, max_results=10)

    assert result.coverage == "complete"
    assert result.dropped == []
    assert result.data["runs"][0]["results"] == []
    parse_sarif(result.data)


def test_build_over_max_results_raises_instead_of_truncating() -> None:
    findings = [
        _finding("uuid-a", location={"file": "src/a.c", "start_line": 3}),
        _finding("uuid-b", location={"file": "src/b.c", "start_line": 9}),
    ]

    with pytest.raises(VendorContractError, match="limit is 1"):
        build_publish_sarif(findings, tool_version=None, max_results=1)


def test_built_document_round_trips_through_parse() -> None:
    findings = [_finding("uuid-a", location={"file": "src/a.c", "start_line": 3})]
    built = build_publish_sarif(findings, tool_version="1.2.3", max_results=10)

    parsed = _parse(built.data)

    assert parsed.coverage == "complete"
    assert parsed.dropped == []
    assert parsed.data == built.data


def test_valid_fixture_parses_completely() -> None:
    result = _parse(VALID.read_bytes())

    assert result.coverage == "complete"
    assert result.dropped == []
    results = result.data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "PARSER-OOB-READ"


def test_result_without_rule_id_is_dropped_and_coverage_is_partial() -> None:
    result = _parse(WITH_DROP.read_bytes())

    assert result.coverage == "partial"
    assert len(result.dropped) == 1
    dropped = result.dropped[0]
    assert dropped["reason"] == "missing ruleId"
    assert dropped["uri"] == "src/loader.py"
    results = result.data["runs"][0]["results"]
    assert [entry["ruleId"] for entry in results] == ["PARSER-OOB-READ"]


def test_result_without_physical_location_is_dropped_and_coverage_is_partial() -> None:
    result = _parse((FIXTURES / "sarif_result_without_physical_location.sarif.json").read_bytes())

    assert result.coverage == "partial"
    assert result.dropped == [
        {
            "reason": "missing physicalLocation",
            "message": "Result with a rule identifier but no physical location.",
            "uri": None,
        }
    ]
    assert [item["ruleId"] for item in result.data["runs"][0]["results"]] == ["PARSER-OOB-READ"]


def test_str_input_parses_like_bytes() -> None:
    result = _parse(VALID.read_text(encoding="utf-8"))

    assert result.data["runs"][0]["results"][0]["ruleId"] == "PARSER-OOB-READ"


def test_mapping_input_parses() -> None:
    document = json.loads(VALID.read_text(encoding="utf-8"))

    result = _parse(document)

    assert result.coverage == "complete"


def test_artifact_over_max_bytes_raises() -> None:
    with pytest.raises(VendorContractError, match="limit is 10"):
        _parse(VALID.read_bytes(), max_bytes=10)


def test_str_artifact_is_measured_in_utf8_bytes() -> None:
    text = VALID.read_text(encoding="utf-8")

    with pytest.raises(VendorContractError):
        _parse(text, max_bytes=len(text.encode("utf-8")) - 1)


def test_document_over_max_runs_raises() -> None:
    document = copy.deepcopy(json.loads(VALID.read_text(encoding="utf-8")))
    document["runs"] = document["runs"] * 2

    with pytest.raises(VendorContractError, match="2 runs; the limit is 1"):
        _parse(document, max_runs=1)


def test_run_over_max_results_per_run_raises() -> None:
    with pytest.raises(VendorContractError, match="limit is 0"):
        _parse(VALID.read_bytes(), max_results_per_run=0)


def test_invalid_document_raises_sarif_validation_error() -> None:
    with pytest.raises(SarifValidationError):
        _parse({"version": "2.1.0", "runs": "not-a-list"})


@pytest.mark.parametrize("edition", ["gitlab", "gitlab_self_managed"])
def test_both_editions_valid_fixture_parses_completely(edition: str) -> None:
    result = _parse((FIXTURES.parent / edition / "sarif_report_valid.sarif.json").read_bytes())

    assert result.coverage == "complete"
    assert result.dropped == []
    assert [entry["ruleId"] for entry in result.data["runs"][0]["results"]] == ["PARSER-OOB-READ"]


@pytest.mark.parametrize("edition", ["gitlab", "gitlab_self_managed"])
def test_both_editions_drop_fixture_is_partial_with_one_drop(edition: str) -> None:
    result = _parse((FIXTURES.parent / edition / "sarif_report_with_drop.sarif.json").read_bytes())

    assert result.coverage == "partial"
    assert result.dropped == [
        {"reason": "missing ruleId", "message": "Result without a rule identifier.", "uri": "src/loader.py"}
    ]
    assert [entry["ruleId"] for entry in result.data["runs"][0]["results"]] == ["PARSER-OOB-READ"]


def test_build_at_exact_max_results_succeeds() -> None:
    findings = [
        _finding("uuid-a", location={"file": "src/a.c", "start_line": 3}),
        _finding("uuid-b", location={"file": "src/b.c", "start_line": 9}),
    ]

    result = build_publish_sarif(findings, tool_version=None, max_results=2)

    assert len(result.data["runs"][0]["results"]) == 2


def test_parse_at_exact_max_bytes_succeeds() -> None:
    data = VALID.read_bytes()

    result = _parse(data, max_bytes=len(data))

    assert result.coverage == "complete"


def test_parse_one_byte_over_max_bytes_raises() -> None:
    data = VALID.read_bytes()

    with pytest.raises(VendorContractError, match=f"limit is {len(data) - 1}"):
        _parse(data, max_bytes=len(data) - 1)


def test_parse_at_exact_max_runs_succeeds() -> None:
    document = copy.deepcopy(json.loads(VALID.read_text(encoding="utf-8")))
    document["runs"] = document["runs"] * 2

    result = _parse(document, max_runs=2)

    assert len(result.data["runs"]) == 2


def test_parse_at_exact_max_results_per_run_succeeds() -> None:
    result = _parse(WITH_DROP.read_bytes(), max_results_per_run=2)

    assert result.coverage == "partial"


def test_parse_one_result_over_max_results_per_run_raises() -> None:
    with pytest.raises(VendorContractError, match="2 results; the limit is 1"):
        _parse(WITH_DROP.read_bytes(), max_results_per_run=1)
