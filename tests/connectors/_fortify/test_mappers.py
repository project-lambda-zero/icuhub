"""OCSF mapping tests for offline Fortify FPR and report records."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from icuhub.connectors._fortify.importers import iter_fortify_xml, iter_fpr
from icuhub.connectors._fortify.mappers import map_fpr_issue, map_report_issue
from icuhub.kit.types import MapContext
from tests.connectors._fortify.test_importers import _fpr


def _ctx() -> MapContext:
    return MapContext(
        connection_id="connection-1",
        tenant_id="tenant-1",
        connector_kind="fortify_ssc",
        received_at=datetime(2026, 11, 10, tzinfo=UTC),
    )


def test_fpr_mapper_preserves_snapshot_identity_cwe_location_and_suppression() -> None:
    raw = next(iter(iter_fpr(_fpr())))
    raw.update(
        {
            "rule": {"accuracy": "5.0", "impact": "4.0", "probability": "5.0"},
            "confidence": "5.0",
            "cwe": 89,
            "cwes": [89, 798],
            "suppressed": True,
            "comments": ["2026-01-01 - (reviewer): confirmed"],
        }
    )

    (finding,) = map_fpr_issue(raw, _ctx())

    assert finding.class_uid == 2002
    assert finding.finding_info.uid == "fortify_fpr:file-uuid-1:inst-1"
    assert finding.finding_info.uid_alt == "inst-1"
    assert finding.metadata.uid == raw["artifact_sha256"]
    assert finding.severity_id == 5
    assert finding.severity == "Critical"
    assert finding.status_id == 3
    assert finding.status == "Suppressed"
    assert finding.vulnerabilities[0].cwe is not None
    assert finding.vulnerabilities[0].cwe.uid == "CWE-89"
    location = finding.vulnerabilities[0].affected_code
    assert location is not None
    assert location[0].file.path == "src/app.py"
    assert location[0].start_line == 12
    assert finding.unmapped is not None
    assert finding.unmapped["fortify"]["audit"]["comments"] == raw["comments"]
    assert finding.unmapped["fortify"]["location_semantics"] == "source_location_v2"
    finding.to_ocsf()


def test_fpr_mapper_without_cwe_keeps_valid_empty_vulnerability_list() -> None:
    raw = next(iter(iter_fpr(_fpr())))

    (finding,) = map_fpr_issue(raw, _ctx())

    assert finding.vulnerabilities == []
    assert finding.severity_id == 1
    assert finding.severity == "Informational"
    finding.to_ocsf()


@pytest.mark.parametrize(
    ("rule", "confidence", "expected_id", "expected_label"),
    [
        ({"accuracy": "5.0", "impact": "4.0", "probability": "5.0"}, "1.0", 4, "High"),
        ({"accuracy": "5.0", "impact": "4.0", "probability": "5.0"}, "5.0", 5, "Critical"),
        ({"accuracy": "5.0", "impact": "1.0", "probability": "5.0"}, "5.0", 3, "Medium"),
        ({"accuracy": "1.0", "impact": "1.0", "probability": "1.0"}, "1.0", 2, "Low"),
        ({"accuracy": "5.0", "impact": "2.5", "probability": "2.5"}, "5.0", 5, "Critical"),
        ({"accuracy": "5.0", "impact": "2.5", "probability": "12.0"}, "1.0", 4, "High"),
        ({"accuracy": "5.0", "impact": "2.4", "probability": "2.5"}, "5.0", 3, "Medium"),
        ({"accuracy": "5.0", "impact": "2.4", "probability": "12.0"}, "1.0", 2, "Low"),
        ({"accuracy": "5.0", "impact": None, "probability": "5.0"}, "5.0", 1, "Informational"),
        ({"accuracy": "5.0", "impact": "", "probability": "5.0"}, "5.0", 1, "Informational"),
        ({"accuracy": "abc", "impact": "4.0", "probability": "5.0"}, "5.0", 1, "Informational"),
        ({"accuracy": "5.0", "impact": "4.0", "probability": "5.0"}, None, 1, "Informational"),
        ({"accuracy": "5.0", "impact": "nan", "probability": "5.0"}, "5.0", 1, "Informational"),
    ],
)
def test_fpr_severity_follows_fortify_likelihood_table(
    rule: dict[str, str | None],
    confidence: str | None,
    expected_id: int,
    expected_label: str,
) -> None:
    raw = next(iter(iter_fpr(_fpr())))
    raw.update({"rule": rule, "confidence": confidence})

    (finding,) = map_fpr_issue(raw, _ctx())

    assert finding.severity_id == expected_id
    assert finding.severity == expected_label
    finding.to_ocsf()


def test_report_mapper_preserves_native_identity_and_dast_evidence_bounds() -> None:
    oversized_response = "HTTP/1.1 200 OK\n" + "x" * 20_000
    scan = f"""<?xml version="1.0"?>
<Scan version="24.2">
  <Issues>
    <Issue>
      <VulnerabilityID>7</VulnerabilityID><URL>https://example.test/a</URL>
      <Name>XSS</Name><Severity>3</Severity><VulnerableSession>session-proof</VulnerableSession>
      <RawResponse>{oversized_response}</RawResponse>
    </Issue>
  </Issues>
</Scan>
""".encode()
    raw = next(iter(iter_fortify_xml(scan)))

    (finding,) = map_report_issue(raw, _ctx())

    report_sha = hashlib.sha256(scan).hexdigest()
    assert finding.finding_info.uid == f"fortify_report:{report_sha}:webinspect_scan:7:https://example.test/a"
    assert finding.finding_info.src_url == "https://example.test/a"
    assert finding.severity_id == 4
    assert finding.severity == "High"
    assert finding.metadata.uid == report_sha
    assert finding.vulnerabilities == []
    evidence = finding.unmapped["fortify"]["evidence"]
    assert evidence["vulnerable_session"]["text"] == "session-proof"
    assert evidence["raw_response"]["truncated"] is True
    assert len(evidence["raw_response"]["text"]) == 16_384
    assert evidence["raw_response"]["sha256"] == hashlib.sha256(oversized_response.encode()).hexdigest()
    finding.to_ocsf()


def test_legacy_report_mapper_uses_native_friority_and_source_location() -> None:
    report = b"""<?xml version="1.0"?>
<ReportDefinition>
  <ReportSection>
    <Title>Results Outline</Title>
    <GroupingSection groupTitle="Injection">
      <Issue iid="i-1">
        <Category>SQL Injection</Category><Abstract>Database proof</Abstract><Friority>High</Friority>
        <Primary><FilePath>src/db.py</FilePath><LineStart>11</LineStart><Snippet>execute()</Snippet></Primary>
      </Issue>
    </GroupingSection>
  </ReportSection>
</ReportDefinition>
"""
    raw = next(iter(iter_fortify_xml(report)))

    (finding,) = map_report_issue(raw, _ctx())

    assert finding.severity_id == 4
    assert finding.finding_info.title == "SQL Injection"
    assert finding.finding_info.desc == "Database proof"
    assert finding.unmapped["fortify"]["primary"]["file_path"] == "src/db.py"
    assert finding.unmapped["fortify"]["primary"]["line"] == 11
    assert finding.unmapped["fortify"]["group_title"] == "Injection"
    finding.to_ocsf()
