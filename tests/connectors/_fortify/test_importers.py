"""Offline tests for the Fortify FPR and XML importers: malicious-input rejection and record shape."""

from __future__ import annotations

import io
import zipfile
from typing import Any

import pytest

from icuhub.connectors._fortify.importers import (
    PROFILE_REPORT_DEFINITION,
    PROFILE_WEBINSPECT_SCAN,
    FortifyImportLimits,
    iter_fortify_xml,
    iter_fpr,
)
from icuhub.kit.errors import BudgetExhausted, VendorContractError

_FVDL = b"""<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl">
  <UUID>file-uuid-1</UUID>
  <Vulnerabilities>
    <Vulnerability>
      <ClassInfo>
        <ClassID>class-1</ClassID>
        <Type>SQL Injection</Type>
        <Kingdom>Input Validation</Kingdom>
        <AnalyzerName>dataflow</AnalyzerName>
        <DefaultSeverity>4.0</DefaultSeverity>
      </ClassInfo>
      <InstanceInfo>
        <InstanceID>inst-1</InstanceID>
        <InstanceSeverity>4.0</InstanceSeverity>
        <Confidence>0.5</Confidence>
      </InstanceInfo>
      <AnalysisInfo>
        <Unified>
          <Trace>
            <Primary>
              <Entry>
                <Node>
                  <SourceLocation path="src/app.py" line="12" lineEnd="12" colStart="4" colEnd="20"/>
                </Node>
              </Entry>
            </Primary>
          </Trace>
        </Unified>
      </AnalysisInfo>
    </Vulnerability>
  </Vulnerabilities>
</FVDL>
"""


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def _fpr(**overrides: bytes) -> bytes:
    members: dict[str, bytes] = {"audit.fvdl": _FVDL}
    members.update(overrides)
    return _zip(members)


def test_fpr_emits_issue_record_with_location_and_file_uuid() -> None:
    records = list(iter_fpr(_fpr()))

    assert len(records) == 1
    record = records[0]
    assert record["instance_id"] == "inst-1"
    assert record["class_id"] == "class-1"
    assert record["path"] == "src/app.py"
    assert record["line"] == 12
    assert record["file_uuid"] == "file-uuid-1"
    assert record["file_uuid_source"] == "fvdl_uuid"
    assert record["location_semantics"] == "source_location_v2"


def test_fpr_rejects_path_traversal_member() -> None:
    with pytest.raises(VendorContractError, match="unsafe archive member name"):
        list(iter_fpr(_fpr(**{"../evil.txt": b"x"})))


def test_fpr_rejects_absolute_and_backslash_member_names() -> None:
    with pytest.raises(VendorContractError, match="unsafe archive member name"):
        list(iter_fpr(_zip({"audit.fvdl": _FVDL, "/etc/passwd": b"x"})))
    # stdlib ZipInfo rewrites "\" to "/" on Windows, so a backslash traversal reaches the guard as "../".
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("audit.fvdl", _FVDL)
        hostile = zipfile.ZipInfo("placeholder")
        hostile.filename = "..\\evil.txt"
        archive.writestr(hostile, b"x")
    with pytest.raises(VendorContractError, match="unsafe archive member name"):
        list(iter_fpr(buffer.getvalue()))


def test_fpr_rejects_non_zip_input() -> None:
    with pytest.raises(VendorContractError, match="not a valid zip"):
        list(iter_fpr(b"not a zip at all"))


def test_fpr_rejects_archive_without_fvdl() -> None:
    with pytest.raises(VendorContractError, match="no audit.fvdl"):
        list(iter_fpr(_zip({"other.txt": b"x"})))


def test_fpr_rejects_duplicate_fvdl_members() -> None:
    with pytest.raises(VendorContractError, match="duplicate archive member name"):
        list(iter_fpr(_zip({"audit.fvdl": _FVDL, "AUDIT.FVDL": _FVDL})))


def test_fpr_rejects_member_count_over_limit() -> None:
    limits = FortifyImportLimits(max_zip_members=1)
    with pytest.raises(BudgetExhausted, match="members"):
        list(iter_fpr(_fpr(**{"extra.txt": b"x"}), limits=limits))


def test_fpr_rejects_declared_size_over_member_limit() -> None:
    limits = FortifyImportLimits(max_member_bytes=10)
    with pytest.raises(BudgetExhausted, match="declares"):
        list(iter_fpr(_fpr(), limits=limits))


def test_fpr_rejects_total_declared_size_over_archive_limit() -> None:
    limits = FortifyImportLimits(max_total_bytes=len(_FVDL) - 1)
    with pytest.raises(BudgetExhausted):
        list(iter_fpr(_fpr(), limits=limits))


def test_fpr_rejects_high_compression_ratio() -> None:
    bomb = b"\x00" * (4 * 1024 * 1024)
    limits = FortifyImportLimits(max_ratio=2)
    with pytest.raises(BudgetExhausted, match="compression ratio"):
        list(iter_fpr(_zip({"audit.fvdl": bomb}), limits=limits))


def test_fpr_rejects_unknown_location_semantics() -> None:
    with pytest.raises(ValueError, match="unknown FPR location semantics"):
        list(iter_fpr(_fpr(), location_semantics="bogus"))  # type: ignore[arg-type]


def test_fpr_rejects_dtd_entity_expansion() -> None:
    entity_fvdl = b"""<?xml version="1.0"?>
<!DOCTYPE FVDL [<!ENTITY boom "AAAAAAAAAA">]>
<FVDL><UUID>&boom;</UUID></FVDL>
"""
    with pytest.raises(VendorContractError, match="invalid XML"):
        list(iter_fpr(_zip({"audit.fvdl": entity_fvdl})))


def test_fpr_rejects_xml_nesting_over_depth_limit() -> None:
    depth = 10
    nested = b"<FVDL>" + b"<a>" * depth + b"<b/>" + b"</a>" * depth + b"</FVDL>"
    limits = FortifyImportLimits(max_xml_depth=4)
    with pytest.raises(VendorContractError, match="nesting exceeds"):
        list(iter_fpr(_zip({"audit.fvdl": nested}), limits=limits))


def test_fpr_rejects_text_over_character_limit() -> None:
    big = b"<FVDL><UUID>" + b"A" * 5000 + b"</UUID></FVDL>"
    # Raise the ratio ceiling so the repetitive payload reaches the text-length guard.
    limits = FortifyImportLimits(max_text_chars=100, max_ratio=10_000)
    with pytest.raises(BudgetExhausted, match="character limit"):
        list(iter_fpr(_zip({"audit.fvdl": big}), limits=limits))


def test_xml_rejects_dtd_entities() -> None:
    payload = b"""<?xml version="1.0"?>
<!DOCTYPE ReportDefinition [<!ENTITY x "y">]>
<ReportDefinition>&x;</ReportDefinition>
"""
    with pytest.raises(VendorContractError, match="invalid XML"):
        list(iter_fortify_xml(payload))


def test_xml_rejects_unsupported_root() -> None:
    with pytest.raises(VendorContractError, match="unsupported Fortify XML root"):
        list(iter_fortify_xml(b"<Other/>"))


def test_xml_rejects_nesting_over_depth_limit() -> None:
    depth = 10
    nested = b"<Scan>" + b"<a>" * depth + b"</a>" * depth + b"</Scan>"
    limits = FortifyImportLimits(max_xml_depth=4)
    with pytest.raises(VendorContractError, match="nesting exceeds"):
        list(iter_fortify_xml(nested, limits=limits))


def test_xml_rejects_document_over_byte_limit() -> None:
    limits = FortifyImportLimits(max_total_bytes=10)
    with pytest.raises(BudgetExhausted, match="byte limit"):
        list(iter_fortify_xml(b"<Scan>" + b"x" * 100 + b"</Scan>", limits=limits))


def test_webinspect_scan_rejects_repeated_identity() -> None:
    scan = b"""<?xml version="1.0"?>
<Scan version="1.0">
  <Issues>
    <Issue><VulnerabilityID>7</VulnerabilityID><URL>http://x/a</URL></Issue>
    <Issue><VulnerabilityID>7</VulnerabilityID><URL>http://x/a</URL></Issue>
  </Issues>
</Scan>
"""
    with pytest.raises(VendorContractError, match="repeats issue identity"):
        list(iter_fortify_xml(scan))


def test_webinspect_scan_emits_profiled_record() -> None:
    scan = b"""<?xml version="1.0"?>
<Scan version="1.0">
  <Issues>
    <Issue><VulnerabilityID>7</VulnerabilityID><URL>http://x/a</URL><Name>XSS</Name><Severity>3</Severity></Issue>
  </Issues>
</Scan>
"""
    records: list[dict[str, Any]] = list(iter_fortify_xml(scan))

    assert len(records) == 1
    assert records[0]["profile"] == PROFILE_WEBINSPECT_SCAN
    assert records[0]["native_id"] == "7:http://x/a"
    assert records[0]["severity"] == 3


def test_report_definition_rejects_missing_results_section() -> None:
    report = b"""<?xml version="1.0"?>
<ReportDefinition><ReportSection><Title>Other</Title></ReportSection></ReportDefinition>
"""
    with pytest.raises(VendorContractError, match="no 'Results Outline'"):
        list(iter_fortify_xml(report))


def test_report_definition_emits_profiled_record() -> None:
    report = b"""<?xml version="1.0"?>
<ReportDefinition>
  <ReportSection>
    <Title>Results Outline</Title>
    <GroupingSection groupTitle="Cat">
      <Issue iid="i-1"><Category>SQL</Category><Abstract>Injection</Abstract></Issue>
    </GroupingSection>
  </ReportSection>
</ReportDefinition>
"""
    records = list(iter_fortify_xml(report))

    assert len(records) == 1
    assert records[0]["profile"] == PROFILE_REPORT_DEFINITION
    assert records[0]["native_id"] == "i-1"
    assert records[0]["group_title"] == "Cat"


def test_report_definition_rejects_repeated_iid() -> None:
    report = b"""<?xml version="1.0"?>
<ReportDefinition>
  <ReportSection>
    <Title>Results Outline</Title>
    <Issue iid="i-1"/>
    <Issue iid="i-1"/>
  </ReportSection>
</ReportDefinition>
"""
    with pytest.raises(VendorContractError, match="repeats iid"):
        list(iter_fortify_xml(report))
