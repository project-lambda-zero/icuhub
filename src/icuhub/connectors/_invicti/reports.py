"""Versioned, bounded Invicti JSON report parsing with exact file identity."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from icuhub.connectors._invicti.records import InvictiIssue, parse_issue
from icuhub.kit.errors import VendorContractError

__all__ = ["DEFAULT_MAX_REPORT_BYTES", "REPORT_PARSER_VERSION", "InvictiReport", "ReportSnapshot", "parse_report"]

DEFAULT_MAX_REPORT_BYTES = 16 * 1024 * 1024
REPORT_PARSER_VERSION = "invicti-json/1"
_REPORT_KEYS = frozenset({"ReportId", "ScanId", "TargetUrl", "ScanDate", "Vulnerabilities"})


class ReportSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str
    file_sha256: str
    report_id: str
    scan_id: str | None
    target_url: str


class InvictiReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: str
    scan_id: str | None
    target_url: str
    scan_date: datetime | None
    file_sha256: str
    parser_version: str
    snapshot: ReportSnapshot
    vulnerabilities: list[InvictiIssue]


def _build_report(
    value: dict[str, Any],
    *,
    digest: str,
    website_id: str | None,
    website_name: str | None,
) -> InvictiReport:
    report_id = value.get("ReportId")
    if not isinstance(report_id, str) or not report_id.strip():
        raise VendorContractError("ReportId is required")
    target_url = value.get("TargetUrl")
    if not isinstance(target_url, str) or not target_url.strip():
        raise VendorContractError("TargetUrl is required")
    scan_id = value.get("ScanId")
    if scan_id is not None and not isinstance(scan_id, str):
        raise VendorContractError("ScanId must be a string")
    vulnerabilities = value.get("Vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise VendorContractError("Vulnerabilities must be an array")
    scan_date = None
    if value.get("ScanDate") is not None:
        try:
            scan_date = datetime.fromisoformat(str(value["ScanDate"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise VendorContractError("ScanDate is invalid") from exc
    issues: list[InvictiIssue] = []
    for index, raw in enumerate(vulnerabilities):
        if not isinstance(raw, dict):
            raise VendorContractError(f"Vulnerabilities[{index}] must be an object")
        issue = parse_issue(raw, website_id=website_id, website_root_url=target_url)
        website = issue.website.model_copy(update={"root_url": target_url, "name": website_name or issue.website.name})
        issues.append(issue.model_copy(update={"scan_id": scan_id, "website": website}))
    snapshot = ReportSnapshot(
        snapshot_id=f"{report_id}:{digest}", file_sha256=digest, report_id=report_id, scan_id=scan_id, target_url=target_url
    )
    return InvictiReport(
        report_id=report_id,
        scan_id=scan_id,
        target_url=target_url,
        scan_date=scan_date,
        file_sha256=digest,
        parser_version=REPORT_PARSER_VERSION,
        snapshot=snapshot,
        vulnerabilities=issues,
    )


def parse_report(
    payload: bytes | str,
    *,
    max_bytes: int = DEFAULT_MAX_REPORT_BYTES,
    website_id: str | None = None,
    website_name: str | None = None,
) -> InvictiReport:
    data = payload.encode() if isinstance(payload, str) else payload
    if len(data) > max_bytes:
        raise VendorContractError(f"report exceeds the {max_bytes} byte limit")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VendorContractError("report is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise VendorContractError("report JSON root must be an object")
    unknown = set(value) - _REPORT_KEYS
    if unknown:
        raise VendorContractError(f"unknown report field {sorted(unknown)[0]!r}")
    return _build_report(
        value,
        digest=hashlib.sha256(data).hexdigest(),
        website_id=website_id,
        website_name=website_name,
    )
