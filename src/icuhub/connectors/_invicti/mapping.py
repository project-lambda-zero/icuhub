"""Invicti normalized records to OCSF 2002 vulnerability findings."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from icuhub.connectors._invicti.evidence import sanitize_proof
from icuhub.connectors._invicti.fingerprints import canonicalize_url, issue_fingerprint
from icuhub.connectors._invicti.records import InvictiIssue, InvictiScanResult
from icuhub.connectors._invicti.reports import InvictiReport
from icuhub.kit.errors import VendorContractError
from icuhub.kit.types import MapContext
from icuhub_schemas import ocsf

__all__ = ["map_issue_to_finding", "map_report_to_findings", "map_scan_result_to_finding"]

_SEVERITY = {
    "BestPractice": (1, "Informational"),
    "Information": (1, "Informational"),
    "Low": (2, "Low"),
    "Medium": (3, "Medium"),
    "High": (4, "High"),
    "Critical": (5, "Critical"),
}
_STATUS = {
    "Present": (1, "New"),
    "Revived": (1, "New"),
    "FixedUnconfirmed": (2, "In Progress"),
    "Ignored": (3, "Suppressed"),
    "FalsePositive": (3, "Suppressed"),
    "FixedConfirmed": (4, "Resolved"),
}
_PRODUCT = ocsf.Product(name="Invicti", vendor_name="Invicti")


def _ms(value: datetime | None, fallback: datetime) -> int:
    moment = value or fallback
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return int(moment.timestamp() * 1000)


def _cwe(value: str | None) -> ocsf.Cwe | None:
    if not value:
        return None
    return ocsf.Cwe(uid=value if value.startswith("CWE-") else f"CWE-{value}")


def _resource(issue: InvictiIssue, ctx: MapContext) -> ocsf.ResourceDetails:
    root = canonicalize_url(issue.website.root_url or issue.location.url)
    website_uid = issue.website.id or hashlib.sha256(root.encode()).hexdigest()[:32]
    return ocsf.ResourceDetails(
        uid=f"web_application:{ctx.connection_id}/{website_uid}",
        uid_alt=canonicalize_url(issue.location.url),
        name=issue.website.name or urlsplit(root).hostname,
        type="web_application",
        hostname=urlsplit(root).hostname,
    )


def _map(
    issue: InvictiIssue,
    ctx: MapContext,
    *,
    scan_id: str | None = None,
    report: InvictiReport | None = None,
) -> ocsf.VulnerabilityFinding:
    cwe = _cwe(issue.classification.cwe)
    cve = None
    if issue.classification.cve:
        cve = ocsf.Cve(uid=issue.classification.cve, cwe=cwe)
    if cve is None and cwe is None:
        raise VendorContractError(f"Invicti issue {issue.id} has neither CVE nor CWE; refusing an invalid OCSF 2002")
    proof = sanitize_proof(issue.proof)
    fields: dict[str, Any] = {
        "verification": {"confirmed": issue.confirmed, "certainty": issue.certainty},
        "accepted_risk": issue.accepted_risk,
        "false_positive": issue.false_positive,
        "assignee": issue.assignee,
        "classification": issue.classification.model_dump(),
        "compliance": issue.compliance.model_dump(),
        "location": issue.location.model_dump(),
        "website": issue.website.model_dump(),
        "proof": proof.model_dump(),
        "scan_id": scan_id or issue.scan_id,
        "state": issue.state,
        "raw_severity": issue.severity,
        "tags": issue.tags,
        "fingerprint": issue_fingerprint(issue),
    }
    if report is not None:
        fields["report"] = {
            "report_id": report.report_id,
            "file_sha256": report.file_sha256,
            "snapshot_id": report.snapshot.snapshot_id,
            "parser_version": report.parser_version,
        }
    severity_id, severity_caption = _SEVERITY.get(issue.severity, (0, "Unknown"))
    status_id, status_caption = _STATUS.get(issue.state, (0, "Unknown"))
    seen = _ms(issue.last_seen, ctx.received_at)
    safe_detail = proof.attack_detail.content if proof.attack_detail else None
    return ocsf.VulnerabilityFinding(
        activity_id=1,
        type_uid=200201,
        time=seen,
        cloud=ocsf.Cloud(provider="Invicti"),
        osint=[],
        metadata=ocsf.Metadata(product=_PRODUCT, uid=report.snapshot.snapshot_id if report else scan_id or issue.scan_id),
        finding_info=ocsf.FindingInfo(
            uid=issue.id,
            title=issue.title,
            desc=safe_detail,
            first_seen_time=_ms(issue.first_seen, ctx.received_at) if issue.first_seen else None,
            last_seen_time=seen,
        ),
        severity_id=severity_id,
        severity=severity_caption,
        status=status_caption,
        status_id=status_id,
        status_detail=issue.state,
        vulnerabilities=[
            ocsf.Vulnerability(
                desc=safe_detail,
                cve=cve,
                cwe=None if cve else cwe,
                references=[issue.location.url],
            )
        ],
        resources=[_resource(issue, ctx)],
        unmapped={"invicti": fields},
    )


def map_issue_to_finding(issue: InvictiIssue, ctx: MapContext) -> ocsf.VulnerabilityFinding:
    return _map(issue, ctx)


def map_scan_result_to_finding(result: InvictiScanResult, ctx: MapContext) -> ocsf.VulnerabilityFinding:
    return _map(result.issue, ctx, scan_id=result.scan_id)


def map_report_to_findings(report: InvictiReport, ctx: MapContext) -> list[ocsf.VulnerabilityFinding]:
    return [_map(issue, ctx, scan_id=report.scan_id, report=report) for issue in report.vulnerabilities]
