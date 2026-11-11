"""Behaviour of SARIF 2.1.0 parsing, dumping, and OCSF-to-SARIF conversion."""

from __future__ import annotations

import json

import pytest

from icuhub_schemas.ocsf import (
    AffectedCode,
    ApplicationSecurityPostureFinding,
    Cve,
    Cwe,
    DetectionFinding,
    File,
    FindingInfo,
    Metadata,
    Product,
    Vulnerability,
    VulnerabilityFinding,
)
from icuhub_schemas.sarif import (
    SARIF_VERSION,
    SarifValidationError,
    dump_sarif,
    findings_to_sarif,
    parse_sarif,
)

_COMMON = {
    "time": 1_700_000_000_000,
    "cloud": {"provider": "on-prem"},
    "osint": [],
    "metadata": Metadata(product=Product(name="scanner")),
}


def _code_location(path: str | None, start: int | None = 3, end: int | None = 5) -> AffectedCode:
    return AffectedCode(file=File(name="app.py", type_id=1, path=path), start_line=start, end_line=end)


def _vulnerability_finding(
    uid: str,
    vulnerabilities: list[Vulnerability],
    severity_id: int = 3,
    title: str | None = "Outdated dependency",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        **_COMMON,
        activity_id=1,
        severity_id=severity_id,
        finding_info=FindingInfo(uid=uid, title=title),
        vulnerabilities=vulnerabilities,
    )


def test_parse_then_dump_round_trip_is_stable() -> None:
    result = findings_to_sarif(
        [
            _vulnerability_finding(
                "f-1",
                [Vulnerability(cve=Cve(uid="CVE-2024-0001"), affected_code=[_code_location("src/app.py")])],
            )
        ],
        tool_name="scanner",
        tool_version="2.0",
    )

    document = dump_sarif(result.log)

    assert document["version"] == SARIF_VERSION
    assert dump_sarif(parse_sarif(json.dumps(document))) == document
    assert parse_sarif(document) == result.log


def test_parse_accepts_bytes() -> None:
    document = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}}]}

    assert parse_sarif(json.dumps(document).encode("utf-8")).runs[0].tool.driver.name == "x"


def test_parse_rejects_schema_violation_with_path() -> None:
    document = {"version": "2.0.0", "runs": [{"tool": {"driver": {"name": "x"}}}]}

    with pytest.raises(SarifValidationError) as raised:
        parse_sarif(document)

    assert raised.value.issues


def test_parse_keeps_rule_index_rank_and_security_severity() -> None:
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "scanner",
                        "rules": [
                            {
                                "id": "R1",
                                "defaultConfiguration": {"level": "error", "rank": 80.0},
                                "properties": {"security-severity": "9.1", "tags": ["security"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "R1",
                        "ruleIndex": 0,
                        "rank": 42.5,
                        "message": {"text": "m"},
                        "properties": {"security-severity": "9.1"},
                    }
                ],
            }
        ],
    }

    log = parse_sarif(document)
    rule = log.runs[0].tool.driver.rules[0]
    result = log.runs[0].results[0]

    assert rule.default_configuration is not None
    assert rule.default_configuration.level == "error"
    assert rule.default_configuration.rank == 80.0
    assert rule.properties is not None
    assert rule.properties.model_dump()["security-severity"] == "9.1"
    assert result.rule_index == 0
    assert result.rank == 42.5
    assert result.properties is not None
    assert result.properties.model_dump()["security-severity"] == "9.1"

    dumped = dump_sarif(log)
    assert dumped["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.1"
    assert dumped["runs"][0]["results"][0]["ruleIndex"] == 0
    assert dumped["runs"][0]["results"][0]["properties"] == {"security-severity": "9.1"}


def test_parse_accepts_schema_sentinel_rank_and_rule_index() -> None:
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "scanner", "rules": [{"id": "R1"}]}},
                "results": [{"ruleIndex": -1, "rank": -1, "message": {"text": "m"}}],
            }
        ],
    }

    result = parse_sarif(document).runs[0].results[0]

    assert result.rule_index == -1
    assert result.rank == -1


def test_parse_rejects_rank_outside_schema_range() -> None:
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "x"}}, "results": [{"rank": 101, "message": {"text": "m"}}]}],
    }

    with pytest.raises(SarifValidationError):
        parse_sarif(document)


def test_parse_rejects_invalid_json() -> None:
    with pytest.raises(SarifValidationError) as raised:
        parse_sarif("{not json")

    assert raised.value.issues[0].path == "$"


def test_rule_id_prefers_cve_then_cwe() -> None:
    result = findings_to_sarif(
        [
            _vulnerability_finding(
                "f-cve",
                [Vulnerability(cve=Cve(uid="CVE-2024-0001"), affected_code=[_code_location("a.py")])],
            ),
            _vulnerability_finding(
                "f-cwe",
                [Vulnerability(cwe=Cwe(uid="CWE-79"), affected_code=[_code_location("b.py")])],
            ),
        ],
        tool_name="scanner",
    )

    assert [item.rule_id for item in result.log.runs[0].results or []] == ["CVE-2024-0001", "CWE-79"]


def test_severity_maps_to_level() -> None:
    findings = [
        _vulnerability_finding(
            f"f-{severity}",
            [Vulnerability(cwe=Cwe(uid="CWE-1"), affected_code=[_code_location("a.py")])],
            severity_id=severity,
        )
        for severity in (1, 3, 5)
    ]

    result = findings_to_sarif(findings, tool_name="scanner")

    assert [item.level for item in result.log.runs[0].results or []] == ["note", "warning", "error"]


def test_code_location_becomes_region_and_uri() -> None:
    result = findings_to_sarif(
        [
            _vulnerability_finding(
                "f-1",
                [Vulnerability(cwe=Cwe(uid="CWE-1"), affected_code=[_code_location("src/app.py", 3, 5)])],
            )
        ],
        tool_name="scanner",
    )

    location = result.log.runs[0].results[0].locations[0].physical_location
    assert location.artifact_location.uri == "src/app.py"
    assert (location.region.start_line, location.region.end_line) == (3, 5)


def test_findings_without_code_location_are_skipped_and_returned() -> None:
    located = _vulnerability_finding(
        "f-located",
        [Vulnerability(cwe=Cwe(uid="CWE-1"), affected_code=[_code_location("a.py")])],
    )
    no_path = _vulnerability_finding(
        "f-no-path",
        [Vulnerability(cwe=Cwe(uid="CWE-1"), affected_code=[_code_location(None)])],
    )
    no_code = _vulnerability_finding("f-no-code", [Vulnerability(cwe=Cwe(uid="CWE-1"))])
    detection = DetectionFinding(**_COMMON, activity_id=1, severity_id=3, finding_info=FindingInfo(uid="f-detect"))
    posture = ApplicationSecurityPostureFinding(
        **_COMMON,
        activity_id=1,
        severity_id=3,
        finding_info=FindingInfo(uid="f-posture"),
        application={"name": "billing"},
    )

    result = findings_to_sarif([located, no_path, no_code, detection, posture], tool_name="scanner")

    assert len(result.log.runs[0].results or []) == 1
    assert result.skipped == (no_path, no_code, detection, posture)


def test_empty_input_yields_valid_empty_run() -> None:
    result = findings_to_sarif([], tool_name="scanner", tool_version=None)

    document = dump_sarif(result.log)

    assert document["runs"] == [{"tool": {"driver": {"name": "scanner"}}, "results": []}]
    assert result.skipped == ()
