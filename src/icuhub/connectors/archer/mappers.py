"""Archer mappers: OCSF 2002/2003 findings and SourceRecord for other streams.

Finding fingerprints exclude severity, status, and record Version: they key on
the mapping version, application/level, vulnerability or CVE identity, device or
application location, and port or plugin component, so re-scans and status
transitions never mint new finding identities.
"""

from datetime import datetime
from typing import Any

from icuhub.kit import MapContext, SourceRecord, VendorContractError, bounded_raw, epoch_ms, fingerprint_for
from icuhub_schemas.ocsf import (
    Cloud,
    Compliance,
    ComplianceFinding,
    Cve,
    Cwe,
    FindingInfo,
    Metadata,
    Product,
    Remediation,
    ResourceDetails,
    Vulnerability,
    VulnerabilityFinding,
)

from .streams import STREAM_SPECS

__all__ = ["map_record"]

_SEVERITY = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
    "information": 1,
    "none": 1,
}


def _field(fields: dict[str, Any], *names: str) -> Any:
    lowered = {str(k).lower(): v for k, v in fields.items()}
    for name in names:
        value = lowered.get(name.lower())
        if isinstance(value, list):
            value = value[0] if value else None
        if value not in (None, ""):
            return value
    return None


def _epoch_or(value: Any, fallback: datetime) -> int:
    try:
        parsed = epoch_ms(value)
    except VendorContractError:
        parsed = None
    if parsed is not None:
        return parsed
    return int(fallback.timestamp() * 1000)


def _severity_id(fields: dict[str, Any]) -> int:
    label = _field(fields, "Severity", "Risk Severity", "Priority")
    if isinstance(label, (int, float)) and not isinstance(label, bool):
        return max(1, min(6, int(label)))
    return _SEVERITY.get(str(label).strip().lower(), 1) if label is not None else 1


def _metadata() -> Metadata:
    return Metadata(product=Product(name="Archer GRC", vendor_name="RSA"))


def _fingerprint(raw: dict[str, Any], fields: dict[str, Any]) -> str:
    vulnerability = _field(fields, "CVE", "Cve", "Vulnerability", "Vulnerability ID", "Title", "Name")
    location = _field(fields, "Device", "Hostname", "Host", "Application", "Asset")
    component = _field(fields, "Port", "Plugin", "Plugin ID", "PluginID", "Check")
    rule = (
        f"{raw.get('record_type')}:v1:{raw.get('application_id')}:{raw.get('level_id')}:"
        f"{vulnerability or raw.get('content_id')}"
    )
    return fingerprint_for(
        "archer",
        rule,
        str(location) if location is not None else str(raw.get("application_id")),
        str(component) if component is not None else str(raw.get("content_id")),
    )


def _finding_info(raw: dict[str, Any], fields: dict[str, Any], ctx: MapContext) -> FindingInfo:
    title = _field(fields, "Title", "Name", "Vulnerability", "Control")
    desc = _field(fields, "Description", "Desc", "Details")
    return FindingInfo(
        uid=_fingerprint(raw, fields),
        uid_alt=str(raw.get("content_id")) if raw.get("content_id") is not None else None,
        title=str(title) if title is not None else None,
        desc=str(desc) if desc is not None else None,
        created_time=_epoch_or(_field(fields, "Created", "First Published", "FirstPublished"), ctx.received_at),
        modified_time=_epoch_or(_field(fields, "LastUpdated", "Last Updated", "Modified"), ctx.received_at),
    )


def _vulnerability_finding(raw: dict[str, Any], ctx: MapContext) -> VulnerabilityFinding:
    fields = raw.get("fields") or {}
    cve = _field(fields, "CVE", "Cve")
    cwe = _field(fields, "CWE", "Cwe")
    # Archer library entries without a CVE use the vendor content id as the
    # vulnerability identifier; OCSF requires exactly one of cve/cwe.
    cve_uid = str(cve) if cve is not None else f"ARCHER-{raw.get('content_id')}"
    title = _field(fields, "Title", "Name", "Vulnerability")
    desc = _field(fields, "Description", "Desc", "Details")
    device = _field(fields, "Device", "Hostname", "Host", "Application", "Asset")
    status = _field(fields, "Status")
    vulnerability = (
        Vulnerability(desc=str(desc) if desc is not None else None, cwe=Cwe(uid=str(cwe)))
        if cve is None and cwe is not None
        else Vulnerability(
            desc=str(desc) if desc is not None else None,
            category=str(_field(fields, "Category") or "") or None,
            cve=Cve(uid=cve_uid, title=str(title) if title is not None else None),
        )
    )
    return VulnerabilityFinding(
        activity_id=1,
        type_uid=200201,
        time=_epoch_or(_field(fields, "LastUpdated", "Last Updated", "Modified"), ctx.received_at),
        severity_id=_severity_id(fields),
        metadata=_metadata(),
        cloud=Cloud(provider="archer"),
        osint=[],
        status=str(status) if status is not None else None,
        finding_info=_finding_info(raw, fields, ctx),
        vulnerabilities=[vulnerability],
        resources=[ResourceDetails(name=str(device))] if device is not None else None,
    )


def _compliance_finding(raw: dict[str, Any], ctx: MapContext) -> ComplianceFinding:
    fields = raw.get("fields") or {}
    status = _field(fields, "Status", "Compliance Status")
    control = _field(fields, "Control", "Control ID", "Title", "Name")
    desc = _field(fields, "Description", "Desc", "Details")
    standard = _field(fields, "Standard", "Framework", "Regulation")
    remediation = _field(fields, "Remediation", "Recommendation", "Remediation Plan")
    return ComplianceFinding(
        activity_id=1,
        type_uid=200301,
        time=_epoch_or(_field(fields, "LastUpdated", "Last Updated", "Modified"), ctx.received_at),
        severity_id=_severity_id(fields),
        metadata=_metadata(),
        cloud=Cloud(provider="archer"),
        osint=[],
        status=str(status) if status is not None else None,
        finding_info=_finding_info(raw, fields, ctx),
        compliance=Compliance(
            status=str(status) if status is not None else None,
            control=str(control) if control is not None else None,
            desc=str(desc) if desc is not None else None,
            standards=[str(standard)] if standard is not None else None,
        ),
        remediation=Remediation(desc=str(remediation)) if remediation is not None else None,
    )


def _source_uid(stream_name: str, raw: dict[str, Any]) -> str:
    if stream_name == "attachments":
        return f"archer:attachments:{raw.get('content_id')}:{raw.get('attachment_id')}"
    if stream_name == "data_feed_runs":
        run = raw.get("run") or {}
        key = run.get("Guid") or run.get("Id") or raw.get("run_index")
        return f"archer:data_feed_runs:{key}"
    return f"archer:{stream_name}:{raw.get('content_id')}"


def _source_record(stream_name: str, raw: dict[str, Any], ctx: MapContext) -> SourceRecord:
    return SourceRecord(
        record_type=stream_name,
        uid=_source_uid(stream_name, raw),
        data={
            "raw": bounded_raw(raw),
            "content_id": raw.get("content_id"),
            "observed_at": ctx.received_at.isoformat(),
        },
    )


def map_record(connector, stream_name: str, raw: dict[str, Any], ctx: MapContext) -> list:
    """Map one raw Archer record to its declared output models."""
    ocsf_class = STREAM_SPECS[stream_name]["ocsf_class"]
    if ocsf_class == 2002:
        return [_vulnerability_finding(raw, ctx)]
    if ocsf_class == 2003:
        return [_compliance_finding(raw, ctx)]
    return [_source_record(stream_name, raw, ctx)]
