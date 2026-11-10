"""Pure Fortify vendor-record to OCSF mapping shared by the Fortify connectors."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

from icuhub.connectors._fortify.importers import PROFILE_REPORT_DEFINITION, PROFILE_WEBINSPECT_SCAN
from icuhub.kit.errors import VendorContractError
from icuhub.kit.mapping import EnumTable, bounded_raw, epoch_ms, severity_id_from_label
from icuhub.kit.types import MapContext
from icuhub_schemas.ocsf import (
    AffectedCode,
    Cloud,
    Cwe,
    File,
    FindingInfo,
    Metadata,
    Product,
    Vulnerability,
    VulnerabilityFinding,
)

__all__ = ["map_fod_issue", "map_fpr_issue", "map_report_issue"]

# Labels not listed here map to OCSF severity 0 (Unknown); no severity is invented.
_FOD_SEVERITY = EnumTable(mapping={"Critical": 5, "High": 4, "Medium": 3, "Low": 2}, default=0)
_FORTIFY_VENDOR = "OpenText"
_FOD_PRODUCT_NAME = "Fortify on Demand"
_FOD_CLOUD_PROVIDER = "fortify_on_demand"
_FPR_PRODUCT_NAME = "Fortify Static Code Analyzer"
_FPR_CLOUD_PROVIDER = "fortify_fpr"
_REPORT_PRODUCT_NAME = "Fortify Report Definition"
_REPORT_CLOUD_PROVIDER = "fortify_report"
_WEBINSPECT_PRODUCT_NAME = "WebInspect"
_WEBINSPECT_CLOUD_PROVIDER = "fortify_webinspect"
# OCSF activity 1 (Create): each snapshot row is an observed finding.
_ACTIVITY_CREATE = 1
_VULNERABILITY_FINDING_CLASS_UID = 2002
# OCSF FileTypeId 1: regular file.
_FILE_TYPE_REGULAR = 1
# OCSF FindingStatusId 3: Suppressed.
_SUPPRESSED_STATUS_ID = 3
_SUPPRESSED_STATUS = "Suppressed"
# Evidence text longer than this is truncated; the full-text SHA-256 keeps it verifiable.
_EVIDENCE_TEXT_CHARS = 16_384

_FPR_SEVERITY = EnumTable(
    mapping={"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}, default=0
)
_REPORT_SEVERITY = EnumTable(
    mapping={"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1, "Informational": 1},
    default=0,
)
# WebInspect native severity 0..4 maps onto OCSF 1..5; any other native value is Unknown (0).
_WEBINSPECT_SEVERITY_IDS = {0: 1, 1: 2, 2: 3, 3: 4, 4: 5}
_WEBINSPECT_SEVERITY_LABELS = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}


def _release_id(raw: dict[str, Any]) -> str:
    value = raw.get("_release_id")
    if not isinstance(value, str) or not value:
        raise VendorContractError("Fortify on Demand issue is missing the injected _release_id")
    return value


def _native_id(raw: dict[str, Any]) -> int:
    value = raw.get("id")
    if isinstance(value, bool) or not isinstance(value, int):
        raise VendorContractError("Fortify on Demand vulnerability id must be an integer")
    return value


def _optional_str(raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    return value if isinstance(value, str) and value else None


def _event_time_ms(raw: dict[str, Any], ctx: MapContext) -> int:
    native = _optional_str(raw, "lastModifiedDate") or _optional_str(raw, "introducedDate")
    observed = epoch_ms(native) if native is not None else None
    if observed is None:
        observed = epoch_ms(ctx.received_at.isoformat())
    if observed is None:
        raise VendorContractError("Fortify on Demand observation time is unavailable")
    return observed


def map_fod_issue(raw: dict[str, Any], ctx: MapContext) -> list[VulnerabilityFinding]:
    """Map one FoD release vulnerability without discarding its three native identifiers."""
    release_id = _release_id(raw)
    native_id = _native_id(raw)
    instance_id = raw.get("instanceId")
    vuln_id = raw.get("vulnId")
    if not isinstance(instance_id, str) or not instance_id:
        raise VendorContractError("Fortify on Demand issue is missing instanceId")
    if not isinstance(vuln_id, str) or not vuln_id:
        raise VendorContractError("Fortify on Demand issue is missing vulnId")
    severity_label = _optional_str(raw, "severityString")
    suppressed = raw.get("isSuppressed") is True
    resolved = raw.get("closedStatus") is True or _optional_str(raw, "closedDate") is not None
    status_id = 3 if suppressed else 4 if resolved else 1
    status = "Suppressed" if suppressed else "Resolved" if resolved else "New"
    product = Product(name=_FOD_PRODUCT_NAME, vendor_name=_FORTIFY_VENDOR)
    unmapped = {
        "id": native_id,
        "vulnId": vuln_id,
        "nativeSeverity": raw.get("severity"),
        "developerStatus": raw.get("developerStatus"),
        "auditorStatus": raw.get("auditorStatus"),
        "category": raw.get("category"),
        "kingdom": raw.get("kingdom"),
        "primaryLocation": raw.get("primaryLocation"),
        "primaryLocationFull": raw.get("primaryLocationFull"),
        "lineNumber": raw.get("lineNumber"),
        "source": raw.get("source"),
        "sink": raw.get("sink"),
        "package": raw.get("package"),
    }
    vulnerabilities: list[Vulnerability] = []
    cwe = raw.get("cwe")
    if isinstance(cwe, str) and cwe.isdigit():
        path = _optional_str(raw, "primaryLocationFull") or _optional_str(raw, "primaryLocation")
        affected_code = None
        if path is not None:
            affected_code = [
                AffectedCode(
                    file=File(name=_basename(path), type_id=_FILE_TYPE_REGULAR, path=path),
                    start_line=raw.get("lineNumber") if isinstance(raw.get("lineNumber"), int) else None,
                )
            ]
        vulnerabilities = [Vulnerability(cwe=Cwe(uid=f"CWE-{cwe}"), affected_code=affected_code)]
    return [
        VulnerabilityFinding(
            time=_event_time_ms(raw, ctx),
            severity_id=severity_id_from_label(severity_label, _FOD_SEVERITY),
            severity=severity_label,
            activity_id=_ACTIVITY_CREATE,
            type_uid=_VULNERABILITY_FINDING_CLASS_UID * 100 + _ACTIVITY_CREATE,
            status_id=status_id,
            status=status,
            finding_info=FindingInfo(
                uid=f"fortify_fod:release:{release_id}:instance:{instance_id}",
                uid_alt=vuln_id,
                title=_optional_str(raw, "category"),
                product=product,
            ),
            vulnerabilities=vulnerabilities,
            metadata=Metadata(
                product=Product(name=_FOD_PRODUCT_NAME, vendor_name=_FORTIFY_VENDOR),
                uid=f"{release_id}:{instance_id}",
            ),
            cloud=Cloud(provider=_FOD_CLOUD_PROVIDER),
            osint=[],
            unmapped={"fortify_fod": unmapped},
            raw_data=bounded_raw(raw),
        )
    ]


def _required_str(raw: dict[str, Any], key: str, source: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise VendorContractError(f"{source} record is missing {key}")
    return value


def _observed_time_ms(ctx: MapContext, source: str) -> int:
    # FPR and report records carry no native timestamp, so the observation time is used.
    observed = epoch_ms(ctx.received_at.isoformat())
    if observed is None:
        raise VendorContractError(f"{source} observation time is unavailable")
    return observed


def _product(name: str) -> Product:
    return Product(name=name, vendor_name=_FORTIFY_VENDOR)


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path)[-1] or path


def _bounded_text(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    return {
        "text": value[:_EVIDENCE_TEXT_CHARS],
        "truncated": len(value) > _EVIDENCE_TEXT_CHARS,
        "sha256": hashlib.sha256(value.encode()).hexdigest(),
    }


def _fpr_severity_label(rule: Any, confidence: Any) -> str:
    """Derive the FPR severity label from rule accuracy, impact, probability, and confidence.

    Follows the DefectDojo Fortify parser ``compute_severity``: likelihood is
    ``accuracy * confidence * probability / 25`` rounded to one decimal. Impact >= 2.5 yields
    Critical when likelihood >= 2.5 and High otherwise; impact < 2.5 yields Medium when
    likelihood >= 2.5 and Low otherwise. A missing or falsy impact, a non-numeric input, or a
    non-finite input yields Informational.
    """
    if not isinstance(rule, dict) or not rule.get("impact"):
        return "Informational"
    try:
        impact = float(rule["impact"])
        accuracy = float(rule.get("accuracy"))
        probability = float(rule.get("probability"))
        confidence_value = float(confidence)
    except (TypeError, ValueError):
        return "Informational"
    if not all(math.isfinite(v) for v in (impact, accuracy, probability, confidence_value)):
        return "Informational"
    likelihood = round(accuracy * confidence_value * probability / 25, 1)
    if impact >= 2.5:
        return "Critical" if likelihood >= 2.5 else "High"
    return "Medium" if likelihood >= 2.5 else "Low"


def _vulnerability_finding(
    *,
    ctx: MapContext,
    source: str,
    product_name: str,
    cloud_provider: str,
    severity_id: int,
    severity: str | None,
    finding_info: FindingInfo,
    vulnerabilities: list[Vulnerability],
    metadata_uid: str,
    raw: dict[str, Any],
    unmapped: dict[str, Any],
    status_id: int | None = None,
    status: str | None = None,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        time=_observed_time_ms(ctx, source),
        severity_id=severity_id,
        severity=severity,
        activity_id=_ACTIVITY_CREATE,
        type_uid=_VULNERABILITY_FINDING_CLASS_UID * 100 + _ACTIVITY_CREATE,
        status_id=status_id,
        status=status,
        finding_info=finding_info,
        vulnerabilities=vulnerabilities,
        metadata=Metadata(product=_product(product_name), uid=metadata_uid),
        cloud=Cloud(provider=cloud_provider),
        osint=[],
        unmapped={"fortify": unmapped},
        raw_data=bounded_raw(raw),
    )


def _fpr_finding(raw: dict[str, Any], ctx: MapContext) -> VulnerabilityFinding:
    file_uuid = _required_str(raw, "file_uuid", "Fortify FPR")
    instance_id = _required_str(raw, "instance_id", "Fortify FPR")
    artifact_sha = _required_str(raw, "artifact_sha256", "Fortify FPR")
    issue_name = _optional_str(raw, "issue_name")
    description = _optional_str(raw, "description")
    path = _optional_str(raw, "path")
    line = raw.get("line")
    suppressed = raw.get("suppressed") is True
    severity_label = _fpr_severity_label(raw.get("rule"), raw.get("confidence"))

    vulnerabilities: list[Vulnerability] = []
    cwe = raw.get("cwe")
    if isinstance(cwe, int) and not isinstance(cwe, bool):
        affected_code = None
        if path is not None:
            affected_code = [
                AffectedCode(
                    file=File(name=_basename(path), type_id=_FILE_TYPE_REGULAR, path=path),
                    start_line=line,
                    end_line=raw.get("line_end"),
                    start_column=raw.get("col_start"),
                    end_column=raw.get("col_end"),
                )
            ]
        vulnerabilities = [Vulnerability(cwe=Cwe(uid=f"CWE-{cwe}"), affected_code=affected_code)]

    unmapped = {
        "file_uuid_source": raw.get("file_uuid_source"),
        "location_semantics": raw.get("location_semantics"),
        "parser_version": raw.get("parser_version"),
        "class_id": raw.get("class_id"),
        "kingdom": raw.get("kingdom"),
        "analyzer": raw.get("analyzer"),
        "default_severity": raw.get("default_severity"),
        "instance_severity": raw.get("instance_severity"),
        "confidence": raw.get("confidence"),
        "rule": raw.get("rule"),
        "cwes": raw.get("cwes"),
        "location": {
            "path": path,
            "line": line,
            "source_line": raw.get("source_line"),
            "line_end": raw.get("line_end"),
            "col_start": raw.get("col_start"),
            "col_end": raw.get("col_end"),
            "snippet_id": raw.get("snippet_id"),
        },
        "audit": {"suppressed": suppressed, "comments": raw.get("comments") or []},
        "snippet": raw.get("snippet"),
        "explanation": raw.get("explanation"),
        "recommendation": raw.get("recommendation"),
        "tips": raw.get("tips"),
    }
    return _vulnerability_finding(
        ctx=ctx,
        source="Fortify FPR",
        product_name=_FPR_PRODUCT_NAME,
        cloud_provider=_FPR_CLOUD_PROVIDER,
        severity_id=severity_id_from_label(severity_label, _FPR_SEVERITY),
        severity=severity_label,
        finding_info=FindingInfo(
            uid=f"fortify_fpr:{file_uuid}:{instance_id}",
            uid_alt=instance_id,
            title=issue_name,
            desc=description,
            product=_product(_FPR_PRODUCT_NAME),
        ),
        vulnerabilities=vulnerabilities,
        metadata_uid=artifact_sha,
        raw=raw,
        unmapped=unmapped,
        status_id=_SUPPRESSED_STATUS_ID if suppressed else None,
        status=_SUPPRESSED_STATUS if suppressed else None,
    )


def _legacy_report_finding(raw: dict[str, Any], ctx: MapContext) -> VulnerabilityFinding:
    report_sha = _required_str(raw, "report_sha256", "Fortify report")
    native_id = _required_str(raw, "native_id", "Fortify report")
    category = _optional_str(raw, "category")
    abstract = _optional_str(raw, "abstract")
    friority = _optional_str(raw, "friority")
    unmapped = {
        "parser_version": raw.get("parser_version"),
        "folder": raw.get("folder"),
        "kingdom": raw.get("kingdom"),
        "primary": raw.get("primary"),
        "source": raw.get("source"),
        "group_title": raw.get("group_title"),
        "group": raw.get("group"),
    }
    return _vulnerability_finding(
        ctx=ctx,
        source="Fortify report",
        product_name=_REPORT_PRODUCT_NAME,
        cloud_provider=_REPORT_CLOUD_PROVIDER,
        severity_id=severity_id_from_label(friority, _REPORT_SEVERITY),
        severity=friority,
        finding_info=FindingInfo(
            uid=f"fortify_report:{report_sha}:{PROFILE_REPORT_DEFINITION}:{native_id}",
            uid_alt=native_id,
            title=category,
            desc=abstract,
            product=_product(_REPORT_PRODUCT_NAME),
        ),
        vulnerabilities=[],
        metadata_uid=report_sha,
        raw=raw,
        unmapped=unmapped,
    )


def _webinspect_finding(raw: dict[str, Any], ctx: MapContext) -> VulnerabilityFinding:
    report_sha = _required_str(raw, "report_sha256", "WebInspect scan")
    native_id = _required_str(raw, "native_id", "WebInspect scan")
    name = _optional_str(raw, "name")
    url = _optional_str(raw, "url")
    severity_id = _WEBINSPECT_SEVERITY_IDS.get(raw.get("severity"), 0)
    severity_label = _WEBINSPECT_SEVERITY_LABELS.get(severity_id)
    unmapped = {
        "parser_version": raw.get("parser_version"),
        "vulnerability_id": raw.get("vulnerability_id"),
        "scan_version": raw.get("scan_version"),
        "check_type_id": raw.get("check_type_id"),
        "engine_type": raw.get("engine_type"),
        "scheme": raw.get("scheme"),
        "host": raw.get("host"),
        "port": raw.get("port"),
        "native_severity": raw.get("severity"),
        "evidence": {
            "vulnerable_session": _bounded_text(raw.get("vulnerable_session")),
            "raw_response": _bounded_text(raw.get("raw_response")),
        },
    }
    return _vulnerability_finding(
        ctx=ctx,
        source="WebInspect scan",
        product_name=_WEBINSPECT_PRODUCT_NAME,
        cloud_provider=_WEBINSPECT_CLOUD_PROVIDER,
        severity_id=severity_id,
        severity=severity_label,
        finding_info=FindingInfo(
            uid=f"fortify_report:{report_sha}:{PROFILE_WEBINSPECT_SCAN}:{native_id}",
            uid_alt=native_id,
            title=name,
            src_url=url,
            product=_product(_WEBINSPECT_PRODUCT_NAME),
        ),
        vulnerabilities=[],
        metadata_uid=report_sha,
        raw=raw,
        unmapped=unmapped,
    )


def map_fpr_issue(raw: dict[str, Any], ctx: MapContext) -> list[VulnerabilityFinding]:
    """Map one offline FPR issue to an OCSF 2002 finding.

    Identity is the artifact-scoped instance id, and the artifact SHA-256 is the metadata uid
    so each snapshot stays attributable. Suppression audit maps to status ``Suppressed``. The
    CWE and source location populate ``vulnerabilities`` only when an integer CWE is present;
    otherwise ``vulnerabilities`` stays empty and the location is kept in ``unmapped``.
    """
    return [_fpr_finding(raw, ctx)]


def map_report_issue(raw: dict[str, Any], ctx: MapContext) -> list[VulnerabilityFinding]:
    """Map one offline Fortify report record to an OCSF 2002 finding.

    Dispatches on the record's ``profile``: legacy ReportDefinition issues and WebInspect scan
    issues each keep their native identity; WebInspect evidence is bounded with a full-text
    SHA-256. Any other profile is a vendor contract violation.
    """
    profile = raw.get("profile")
    if profile == PROFILE_REPORT_DEFINITION:
        return [_legacy_report_finding(raw, ctx)]
    if profile == PROFILE_WEBINSPECT_SCAN:
        return [_webinspect_finding(raw, ctx)]
    raise VendorContractError(f"unsupported Fortify report profile {profile!r}")
