"""Normalized Invicti vendor records (Enterprise REST API 1.0 and desktop JSON reports).

Vendor payloads use PascalCase and differ slightly between endpoints. ``parse_*`` helpers
validate against an explicit known-key set: an unknown vendor key raises
``VendorContractError`` rather than being silently dropped, so template or schema drift is
visible instead of lossy.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from icuhub.kit.errors import VendorContractError

__all__ = [
    "InvictiClassification",
    "InvictiCompliance",
    "InvictiIssue",
    "InvictiLocation",
    "InvictiProof",
    "InvictiScan",
    "InvictiScanResult",
    "InvictiWebsite",
    "parse_issue",
    "parse_scan",
    "parse_scan_result",
]


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InvictiLocation(_Record):
    url: str
    parameter: str | None = None
    parameter_type: str | None = None


class InvictiWebsite(_Record):
    id: str | None = None
    name: str | None = None
    root_url: str | None = None


class InvictiProof(_Record):
    attack_detail: str | None = None
    http_request: str | None = None
    http_response: str | None = None
    proof_of_concept: str | None = None


class InvictiClassification(_Record):
    cwe: str | None = None
    cve: str | None = None
    owasp_top_ten_2021: str | None = None
    pci_dss_40: str | None = None


class InvictiCompliance(_Record):
    pci_dss_40: str | None = None


class InvictiIssue(_Record):
    id: str
    title: str
    issue_type: str
    severity: str
    state: str
    confirmed: bool | None
    accepted_risk: bool
    false_positive: bool
    certainty: int | None
    assignee: str | None = None
    location: InvictiLocation
    website: InvictiWebsite
    proof: InvictiProof
    classification: InvictiClassification
    compliance: InvictiCompliance
    first_seen: datetime | None
    last_seen: datetime | None
    scan_id: str | None
    tags: list[str]


class InvictiScan(_Record):
    id: str
    website: InvictiWebsite
    state: str
    completed: bool
    initiated: datetime | None
    state_changed: datetime | None
    scan_task_profile_id: str | None
    total_vulnerability_count: int | None


class InvictiScanResult(_Record):
    scan_id: str
    issue_url: str | None
    issue: InvictiIssue


_ISSUE_KEYS = frozenset(
    {
        "Id",
        "ExternalId",
        "IssueUrl",
        "WebsiteId",
        "WebsiteName",
        "WebsiteRootUrl",
        "Title",
        "Name",
        "Type",
        "Url",
        "Parameter",
        "Severity",
        "State",
        "IsPresent",
        "IsAddressed",
        "IsRetest",
        "LatestVulnerabilityIsConfirmed",
        "Confirmed",
        "Certainty",
        "Assignee",
        "AcceptedRisk",
        "FalsePositive",
        "FirstSeenDate",
        "LastSeenDate",
        "UpdatedDate",
        "LatestScanId",
        "Parameters",
        "ProofOfConcept",
        "AttackDetail",
        "HttpRequest",
        "HttpResponse",
        "VulnerabilityDetail",
        "Remedy",
        "RemedyReferences",
        "ExternalReferences",
        "Classification",
        "ClassificationLinks",
        "Compliance",
        "Cwe",
        "Cve",
        "Tags",
    }
)
_CLASSIFICATION_KEYS = frozenset({"Cwe", "Cve", "OwaspTopTen2021", "PciDss40"})
_COMPLIANCE_KEYS = frozenset({"PciDss40"})
_PARAMETER_KEYS = frozenset({"Name", "Value", "TypeName", "IsAttackParameter"})
_SCAN_KEYS = frozenset(
    {
        "Id",
        "WebsiteId",
        "WebsiteName",
        "TargetUrl",
        "State",
        "IsCompleted",
        "Initiated",
        "StateChanged",
        "ScanTaskProfileId",
        "TotalVulnerabilityCount",
    }
)


def _reject_unknown(raw: dict[str, Any], known: frozenset[str], where: str) -> None:
    for key in raw:
        if key not in known:
            raise VendorContractError(f"unknown vendor field {key!r} in {where}")


def _required_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise VendorContractError(f"missing or invalid required field {key!r}")
    return value


def _optional_str(raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise VendorContractError(f"field {key!r} must be a string")
    return value


def _timestamp(raw: dict[str, Any], key: str, *, required: bool = False) -> datetime | None:
    value = raw.get(key)
    if value is None:
        if required:
            raise VendorContractError(f"missing or invalid required field {key!r}")
        return None
    if not isinstance(value, str):
        raise VendorContractError(f"field {key!r} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VendorContractError(f"field {key!r} is not a valid timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _parse_classification(raw: dict[str, Any]) -> InvictiClassification:
    nested = raw.get("Classification") or {}
    if not isinstance(nested, dict):
        raise VendorContractError("field 'Classification' must be an object")
    _reject_unknown(nested, _CLASSIFICATION_KEYS, "Classification")
    cwe = _optional_str(nested, "Cwe") or _optional_str(raw, "Cwe")
    cve = _optional_str(nested, "Cve") or _optional_str(raw, "Cve")
    return InvictiClassification(
        cwe=cwe,
        cve=cve,
        owasp_top_ten_2021=_optional_str(nested, "OwaspTopTen2021"),
        pci_dss_40=_optional_str(nested, "PciDss40"),
    )


def _parse_compliance(raw: dict[str, Any]) -> InvictiCompliance:
    nested = raw.get("Compliance") or {}
    if not isinstance(nested, dict):
        raise VendorContractError("field 'Compliance' must be an object")
    _reject_unknown(nested, _COMPLIANCE_KEYS, "Compliance")
    return InvictiCompliance(pci_dss_40=_optional_str(nested, "PciDss40"))


def _parse_location(raw: dict[str, Any]) -> InvictiLocation:
    parameter = _optional_str(raw, "Parameter")
    parameter_type: str | None = None
    parameters = raw.get("Parameters") or []
    if not isinstance(parameters, list):
        raise VendorContractError("field 'Parameters' must be a list")
    attack_parameter: dict[str, Any] | None = None
    for entry in parameters:
        if not isinstance(entry, dict):
            raise VendorContractError("field 'Parameters' entries must be objects")
        _reject_unknown(entry, _PARAMETER_KEYS, "Parameters")
        if entry.get("IsAttackParameter"):
            attack_parameter = entry
            break
    chosen = attack_parameter or (parameters[0] if parameters else None)
    if chosen is not None:
        parameter = parameter or _optional_str(chosen, "Name")
        parameter_type = _optional_str(chosen, "TypeName")
    return InvictiLocation(
        url=_required_str(raw, "Url"), parameter=parameter, parameter_type=parameter_type
    )


def parse_issue(
    raw: dict[str, Any],
    *,
    website_id: str | None = None,
    website_name: str | None = None,
    website_root_url: str | None = None,
    scan_id: str | None = None,
) -> InvictiIssue:
    """Normalize one issue object from ``allissues``, ``get``, scan results, or a report."""
    if not isinstance(raw, dict):
        raise VendorContractError("issue record must be a JSON object")
    _reject_unknown(raw, _ISSUE_KEYS, "issue")
    issue_id = raw.get("Id") or raw.get("ExternalId")
    if not isinstance(issue_id, str) or not issue_id:
        raise VendorContractError("missing or invalid required field 'Id'")
    confirmed = raw.get("LatestVulnerabilityIsConfirmed", raw.get("Confirmed"))
    if confirmed is not None and not isinstance(confirmed, bool):
        raise VendorContractError("field 'Confirmed' must be a boolean")
    state = _required_str(raw, "State")
    accepted_risk = raw.get("AcceptedRisk")
    false_positive = raw.get("FalsePositive")
    certainty = raw.get("Certainty")
    if certainty is not None and not isinstance(certainty, int):
        raise VendorContractError("field 'Certainty' must be an integer")
    tags = raw.get("Tags") or []
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise VendorContractError("field 'Tags' must be a list of strings")
    return InvictiIssue(
        id=issue_id,
        title=_required_str(raw, "Title"),
        issue_type=_optional_str(raw, "Type") or "Invicti",
        severity=_required_str(raw, "Severity"),
        state=state,
        confirmed=confirmed,
        accepted_risk=accepted_risk if isinstance(accepted_risk, bool) else state == "AcceptedRisk",
        false_positive=false_positive if isinstance(false_positive, bool) else state == "FalsePositive",
        certainty=certainty,
        assignee=_optional_str(raw, "Assignee"),
        location=_parse_location(raw),
        website=InvictiWebsite(
            id=website_id or _optional_str(raw, "WebsiteId"),
            name=website_name or _optional_str(raw, "WebsiteName"),
            root_url=website_root_url or _optional_str(raw, "WebsiteRootUrl"),
        ),
        proof=InvictiProof(
            attack_detail=_optional_str(raw, "AttackDetail"),
            http_request=_optional_str(raw, "HttpRequest"),
            http_response=_optional_str(raw, "HttpResponse"),
            proof_of_concept=_optional_str(raw, "ProofOfConcept"),
        ),
        classification=_parse_classification(raw),
        compliance=_parse_compliance(raw),
        first_seen=_timestamp(raw, "FirstSeenDate"),
        last_seen=_timestamp(raw, "LastSeenDate", required=True),
        scan_id=_optional_str(raw, "LatestScanId") or scan_id,
        tags=tags,
    )


def parse_scan(raw: dict[str, Any]) -> InvictiScan:
    """Normalize one scan execution record from ``scans/list*``."""
    if not isinstance(raw, dict):
        raise VendorContractError("scan record must be a JSON object")
    _reject_unknown(raw, _SCAN_KEYS, "scan")
    state = _required_str(raw, "State")
    completed = raw.get("IsCompleted")
    total = raw.get("TotalVulnerabilityCount")
    if total is not None and not isinstance(total, int):
        raise VendorContractError("field 'TotalVulnerabilityCount' must be an integer")
    return InvictiScan(
        id=_required_str(raw, "Id"),
        website=InvictiWebsite(
            id=_optional_str(raw, "WebsiteId"),
            name=_optional_str(raw, "WebsiteName"),
            root_url=_optional_str(raw, "TargetUrl"),
        ),
        state=state,
        completed=completed if isinstance(completed, bool) else state == "Complete",
        initiated=_timestamp(raw, "Initiated"),
        state_changed=_timestamp(raw, "StateChanged"),
        scan_task_profile_id=_optional_str(raw, "ScanTaskProfileId"),
        total_vulnerability_count=total,
    )


def parse_scan_result(
    raw: dict[str, Any],
    *,
    scan_id: str,
    website_id: str | None = None,
    website_name: str | None = None,
) -> InvictiScanResult:
    """Normalize one per-scan observation from ``scans/result/{id}``."""
    if not isinstance(raw, dict):
        raise VendorContractError("scan result record must be a JSON object")
    return InvictiScanResult(
        scan_id=scan_id,
        issue_url=_optional_str(raw, "IssueUrl"),
        issue=parse_issue(
            raw,
            website_id=website_id,
            website_name=website_name,
            scan_id=scan_id,
        ),
    )
