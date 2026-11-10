"""Pure Prisma Cloud raw-record to OCSF and source-record mapping."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from icuhub.kit.types import MapContext, SourceRecord
from icuhub_schemas import ocsf

__all__ = [
    "DETECTION_POLICY_TYPES",
    "map_account",
    "map_alert",
    "map_asset_finding",
    "map_cspm_audit",
    "map_nonfinding",
    "map_runtime_detection",
    "parse_ms",
]

DETECTION_POLICY_TYPES = frozenset({"anomaly", "audit_event", "data", "network"})
_SEVERITY = {"informational": 1, "info": 1, "low": 2, "medium": 3, "moderate": 3, "high": 4, "critical": 5}
_PRODUCT = ocsf.Product(name="Prisma Cloud", vendor_name="Palo Alto Networks")
_MAX_UNMAPPED_BYTES = 32 * 1024


def parse_ms(value: Any, default: datetime | None = None) -> int:
    if value is None:
        if default is None:
            return 0
        return int(default.timestamp() * 1000)
    if isinstance(value, (int, float)):
        number = int(value)
        return number // 1000 if 0 < number < 100_000_000_000 else number
    text = str(value).strip()
    if text.isdigit():
        return parse_ms(int(text), default)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return parse_ms(None, default)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp() * 1000)


def _severity(raw: Any) -> tuple[int, str | None]:
    label = str(raw or "informational").lower()
    return _SEVERITY.get(label, 99), str(raw) if raw is not None else None


def _unmapped(raw: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(raw, sort_keys=True, default=str).encode()
    if len(encoded) <= _MAX_UNMAPPED_BYTES:
        return dict(raw)
    return {
        "prisma": {
            "omitted": True,
            "size_bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    }


def _resources(resource: dict[str, Any] | None, fallback_uid: str | None = None) -> list[ocsf.ResourceDetails]:
    resource = resource or {}
    uid = resource.get("rrn") or resource.get("id") or fallback_uid
    return [
        ocsf.ResourceDetails(
            uid=str(uid) if uid is not None else None,
            uid_alt=str(resource.get("id")) if resource.get("id") is not None else None,
            name=resource.get("name") or resource.get("hostname"),
            type=resource.get("resourceType") or resource.get("type"),
            region=resource.get("regionId") or resource.get("region"),
            provider=resource.get("cloudType") or resource.get("provider"),
            namespace=resource.get("accountId") or resource.get("account"),
            hostname=resource.get("hostname"),
            labels=list(resource.get("collections") or []) or None,
        )
    ]


def _base(raw: dict[str, Any], ctx: MapContext, *, uid: str, title: str, time_value: Any) -> dict[str, Any]:
    severity_id, severity = _severity(raw.get("severity"))
    status = str(raw.get("status") or "open").lower()
    return {
        "activity_id": 1,
        "time": parse_ms(time_value, ctx.received_at),
        "cloud": ocsf.Cloud(provider="Prisma Cloud"),
        "osint": [],
        "finding_info": ocsf.FindingInfo(uid=uid, title=title, desc=raw.get("description") or raw.get("message")),
        "severity_id": severity_id,
        "severity": severity,
        "status_id": 1 if status in {"open", "active", "new"} else 2,
        "status": status,
        "resources": _resources(raw.get("resource"), str(raw.get("id")) if raw.get("id") is not None else None),
        "metadata": ocsf.Metadata(product=_PRODUCT, uid=ctx.connection_id),
        "unmapped": _unmapped(raw),
    }


def map_alert(raw: dict[str, Any], ctx: MapContext, finding_kind: str) -> list[Any]:
    policy = raw.get("policy") or {}
    policy_type = str(policy.get("policyType") or raw.get("policyType") or "config").lower()
    expected = {"compliance": "config", "vulnerability": "vulnerability"}.get(finding_kind)
    if expected is not None and policy_type != expected:
        return []
    if finding_kind == "detection" and policy_type not in DETECTION_POLICY_TYPES:
        return []
    uid = str(raw.get("id") or raw.get("alertId") or "")
    if not uid:
        return []
    title = str(policy.get("name") or raw.get("title") or f"Prisma alert {uid}")
    base = _base(raw, ctx, uid=uid, title=title, time_value=raw.get("time") or raw.get("alertTime"))
    remediation = policy.get("remediation") or {}
    remediation_text = remediation.get("description") or remediation.get("cliScript") or raw.get("remediation")
    if finding_kind == "vulnerability":
        cve_values = raw.get("cves") or raw.get("cveList") or policy.get("cves") or []
        if isinstance(cve_values, str):
            cve_values = [cve_values]
        cve = raw.get("cve") or policy.get("cve") or (cve_values[0] if cve_values else None)
        cwe = raw.get("cwe") or policy.get("cwe")
        vulnerability = ocsf.Vulnerability(
            desc=raw.get("description") or policy.get("description"),
            cve=ocsf.Cve(uid=str(cve)) if cve else None,
            cwe=ocsf.Cwe(uid=str(cwe) if str(cwe).startswith("CWE-") else f"CWE-{cwe}") if cwe else None,
            references=list(raw.get("references") or []) or None,
        )
        if not (cve or cwe):
            return []
        return [ocsf.VulnerabilityFinding(**base, vulnerabilities=[vulnerability])]
    if finding_kind == "detection":
        return [ocsf.DetectionFinding(**base, message=raw.get("message") or title)]
    metadata = raw.get("complianceMetadata") or []
    standards = [str(item.get("standardName")) for item in metadata if item.get("standardName")]
    control = str(policy.get("policyId") or raw.get("policyId") or uid)
    return [
        ocsf.ComplianceFinding(
            **base,
            compliance=ocsf.Compliance(
                control=control,
                desc=policy.get("description") or title,
                standards=standards,
                checks=[ocsf.Check(uid=uid, name=title, status=str(raw.get("status") or "open"))],
            ),
            remediation=ocsf.Remediation(desc=str(remediation_text)) if remediation_text else None,
        )
    ]


def map_asset_finding(raw: dict[str, Any], ctx: MapContext, finding_kind: str) -> list[Any]:
    asset = raw.get("_asset") or {}
    finding = raw.get("_finding")
    if not isinstance(finding, dict):
        return []
    asset_uid = str(asset.get("_id") or asset.get("id") or asset.get("digest") or asset.get("hostname") or "unknown")
    finding_id = str(finding.get("id") or finding.get("cve") or finding.get("ruleName") or "unknown")
    uid = f"{asset_uid}:{finding_id}"
    merged = {**finding, "resource": asset, "status": finding.get("status") or "open"}
    base = _base(merged, ctx, uid=uid, title=str(finding.get("title") or finding_id), time_value=finding.get("time") or asset.get("time"))
    base["resources"] = _resources(asset, asset_uid)
    if finding_kind == "vulnerability":
        cve = finding.get("cve") or finding.get("id")
        if not cve or not str(cve).startswith("CVE-"):
            return []
        package_name = finding.get("packageName") or finding.get("package")
        package = None
        if package_name:
            package = ocsf.AffectedPackage(
                name=str(package_name),
                version=str(finding.get("packageVersion") or "unknown"),
                purl=finding.get("purl"),
                path=finding.get("packagePath"),
            )
        return [
            ocsf.VulnerabilityFinding(
                **base,
                vulnerabilities=[
                    ocsf.Vulnerability(
                        desc=finding.get("description"),
                        cve=ocsf.Cve(uid=str(cve)),
                        references=[finding["link"]] if finding.get("link") else None,
                        affected_packages=[package] if package else None,
                    )
                ],
            )
        ]
    control = str(finding.get("id") or finding.get("title") or finding_id)
    return [
        ocsf.ComplianceFinding(
            **base,
            compliance=ocsf.Compliance(
                control=control,
                desc=finding.get("description"),
                checks=[ocsf.Check(uid=uid, name=finding.get("title") or control, status=finding.get("status") or "open")],
            ),
            remediation=ocsf.Remediation(desc=str(finding["remediation"])) if finding.get("remediation") else None,
        )
    ]


def map_runtime_detection(raw: dict[str, Any], ctx: MapContext) -> list[Any]:
    uid = str(raw.get("id") or raw.get("auditId") or raw.get("_id") or "")
    if not uid:
        return []
    title = str(raw.get("ruleName") or raw.get("title") or raw.get("category") or f"Prisma runtime event {uid}")
    base = _base(raw, ctx, uid=uid, title=title, time_value=raw.get("time") or raw.get("timestamp"))
    return [ocsf.DetectionFinding(**base, message=raw.get("message") or title)]


def map_cspm_audit(raw: dict[str, Any], ctx: MapContext) -> list[Any]:
    uid = str(raw.get("id") or raw.get("eventId") or "")
    if not uid:
        return []
    action = str(raw.get("action") or "UNKNOWN").upper()
    activity = {"CREATE": 1, "READ": 2, "UPDATE": 3, "DELETE": 4}.get(action, 99)
    success = str(raw.get("status") or "success").lower() in {"success", "succeeded", "ok"}
    user = raw.get("user") or raw.get("username")
    resource_id = raw.get("resourceId")
    return [
        ocsf.ApiActivity(
            activity_id=activity,
            type_uid=600300 + activity,
            time=parse_ms(raw.get("timestamp") or raw.get("time"), ctx.received_at),
            severity_id=1,
            cloud=ocsf.Cloud(provider="Prisma Cloud"),
            osint=[],
            metadata=ocsf.Metadata(product=_PRODUCT, uid=uid),
            actor=ocsf.Actor(user=ocsf.User(uid=str(user), name=str(user)) if user else None, app_name="Prisma Cloud"),
            api=ocsf.Api(operation=action, service=ocsf.Service(name="Prisma Cloud")),
            src_endpoint=ocsf.NetworkEndpoint(name=str(raw.get("account") or user or "Prisma Cloud")),
            status_id=1 if success else 2,
            status=str(raw.get("status") or "success"),
            resources=_resources({"uid": resource_id, "name": raw.get("resourceType")}, str(resource_id) if resource_id else uid),
            unmapped=_unmapped(raw),
        )
    ]


def map_nonfinding(raw: dict[str, Any], ctx: MapContext, record_type: str, class_uid: int) -> list[SourceRecord]:
    uid = str(raw.get("id") or raw.get("_id") or raw.get("accountId") or raw.get("name") or hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest())
    data = {
        "class_uid": class_uid,
        "time": parse_ms(raw.get("time") or raw.get("lastModifiedTs") or raw.get("timestamp"), ctx.received_at),
        "metadata": {"product": {"name": "Prisma Cloud", "vendor_name": "Palo Alto Networks"}},
        "record_type": record_type,
        "source": raw,
    }
    if record_type == "cloud_account":
        data["account"] = {
            "uid": str(raw.get("accountId") or raw.get("id") or uid),
            "name": raw.get("name"),
            "type": raw.get("cloudType"),
        }
    return [SourceRecord(record_type=record_type, uid=f"prisma:{record_type}:{uid}", revision=str(raw.get("lastModifiedTs") or raw.get("time") or "") or None, data=data)]


def map_account(raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
    return map_nonfinding(raw, ctx, "cloud_account", 3004)
