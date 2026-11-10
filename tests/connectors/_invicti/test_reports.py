"""Versioned bounded Invicti JSON report parser tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors._invicti import (
    DEFAULT_MAX_REPORT_BYTES,
    REPORT_PARSER_VERSION,
    InvictiReport,
    parse_report,
)
from icuhub.kit.errors import VendorContractError

_FIXTURES = Path(__file__).parents[2] / "fixtures"


def test_enterprise_report_parses_with_file_and_report_snapshot_identity() -> None:
    data = (_FIXTURES / "invicti_enterprise" / "report.json").read_bytes()

    report = parse_report(data)

    assert isinstance(report, InvictiReport)
    assert report.report_id == "report-enterprise-001"
    assert report.scan_id == "6dc7a92f-94ab-4f7c-b60f-000000000401"
    assert report.target_url == "https://shop.example.test/"
    assert report.file_sha256 == hashlib.sha256(data).hexdigest()
    assert report.parser_version == REPORT_PARSER_VERSION
    assert report.snapshot.snapshot_id == f"report-enterprise-001:{hashlib.sha256(data).hexdigest()}"
    assert report.snapshot.file_sha256 == report.file_sha256
    assert len(report.vulnerabilities) == 1
    issue = report.vulnerabilities[0]
    assert issue.scan_id == report.scan_id
    assert issue.website.root_url == report.target_url
    assert issue.proof.http_request is not None
    assert issue.proof.http_response is not None


def test_standard_report_can_receive_configured_website_identity() -> None:
    data = (_FIXTURES / "invicti_standard" / "report.json").read_bytes()

    report = parse_report(data, website_id="website-configured-1", website_name="Blog")

    issue = report.vulnerabilities[0]
    assert issue.website.id == "website-configured-1"
    assert issue.website.name == "Blog"
    assert issue.website.root_url == "https://blog.example.test/"
    assert issue.accepted_risk is False
    assert issue.false_positive is False


def test_string_and_equivalent_bytes_have_distinct_exact_file_digests() -> None:
    raw = (_FIXTURES / "invicti_standard" / "report.json").read_bytes()
    text = raw.decode("utf-8").strip()

    original = parse_report(raw)
    compact = parse_report(text)

    assert original.report_id == compact.report_id
    assert original.file_sha256 != compact.file_sha256
    assert original.snapshot.snapshot_id != compact.snapshot.snapshot_id


@pytest.mark.parametrize(
    "payload",
    [
        b"<?xml version=\"1.0\"?><Report><Vulnerabilities>[]</Vulnerabilities></Report>",
        b"<html><body>{\"ReportId\": \"forged\"}</body></html>",
        b"not json",
        b"{broken",
    ],
)
def test_non_json_content_is_rejected(payload: bytes) -> None:
    with pytest.raises(VendorContractError, match="JSON"):
        parse_report(payload)


@pytest.mark.parametrize("payload", [b"[]", b"null", b'"report"'])
def test_non_object_json_root_is_rejected(payload: bytes) -> None:
    with pytest.raises(VendorContractError, match="object"):
        parse_report(payload)


def test_oversize_report_is_rejected_before_decoding() -> None:
    with pytest.raises(VendorContractError, match="byte limit"):
        parse_report(b" " * 101 + b"{}", max_bytes=100)


def test_default_report_size_cap_is_bounded() -> None:
    assert 0 < DEFAULT_MAX_REPORT_BYTES <= 16 * 1024 * 1024


def test_missing_report_identity_is_rejected() -> None:
    raw: dict[str, Any] = json.loads((_FIXTURES / "invicti_standard" / "report.json").read_text(encoding="utf-8"))
    del raw["ReportId"]

    with pytest.raises(VendorContractError, match="ReportId"):
        parse_report(json.dumps(raw))


def test_unknown_report_field_is_rejected() -> None:
    raw: dict[str, Any] = json.loads((_FIXTURES / "invicti_standard" / "report.json").read_text(encoding="utf-8"))
    raw["Unexpected"] = True

    with pytest.raises(VendorContractError, match="Unexpected"):
        parse_report(json.dumps(raw))


def test_report_replay_has_stable_snapshot_identity() -> None:
    data = (_FIXTURES / "invicti_standard" / "report.json").read_bytes()

    first = parse_report(data)
    second = parse_report(data)

    assert first.snapshot == second.snapshot
    assert first.vulnerabilities == second.vulnerabilities
