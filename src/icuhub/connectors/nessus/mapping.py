"""Nessus raw-record to OCSF mapping (native severity preserved; no CVSS recomputation)."""

from __future__ import annotations

import hashlib
from typing import Any

from icuhub.connectors.nessus.models import NessusFindingRecord
from icuhub.kit.types import MapContext
from icuhub_schemas import ocsf

__all__ = ["event_uid", "is_compliance", "map_compliance", "map_finding"]

_SEVERITY_ID = {0: 1, 1: 2, 2: 3, 3: 4, 4: 5}
_SEVERITY_LABEL = {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
_PRODUCT = ocsf.Product(name="Nessus", vendor_name="Tenable")


def event_uid(report: dict[str, Any], host: dict[str, Any], item: dict[str, Any]) -> str:
    basis = "|".join([report["run_uid"], host["key"], item["plugin_id"], str(item["ordinal"])])
    return hashlib.sha256(basis.encode()).hexdigest()


def is_compliance(item: dict[str, Any]) -> bool:
    return bool(item.get("compliance")) or item.get("plugin_family") == "Policy Compliance"


def _resources(host: dict[str, Any]) -> list[ocsf.ResourceDetails]:
    return [
        ocsf.ResourceDetails(
            uid=host.get("uid") or host["key"],
            name=host["name"],
            hostname=host.get("fqdn") or host["name"],
            ip=host.get("ip"),
        )
    ]


def _vulnerability(item: dict[str, Any]) -> ocsf.Vulnerability:
    cves = item.get("cves") or []
    cwes = item.get("cwes") or []
    references = list(item.get("references") or [])
    return ocsf.Vulnerability(
        desc=item.get("description") or item.get("synopsis"),
        cve=ocsf.Cve(uid=cves[0]) if cves else None,
        cwe=ocsf.Cwe(uid=cwes[0] if str(cwes[0]).startswith("CWE-") else f"CWE-{cwes[0]}") if cwes else None,
        references=references or None,
    )


def _base(record: NessusFindingRecord, ctx: MapContext) -> dict[str, Any]:
    item = record.item
    return {
        "activity_id": 1,
        "time": int(ctx.received_at.timestamp() * 1000),
        "cloud": ocsf.Cloud(provider="on-prem"),
        "osint": [],
        "finding_info": ocsf.FindingInfo(
            uid=record.event_uid,
            title=item.plugin_name or f"Nessus plugin {item.plugin_id}",
            desc=item.description or item.synopsis,
        ),
        "severity_id": _SEVERITY_ID.get(item.severity or 0, 1),
        "severity": _SEVERITY_LABEL.get(item.severity or 0),
        "status_id": 1,
        "status": "open",
        "resources": _resources(record.host.model_dump()),
        "metadata": ocsf.Metadata(product=_PRODUCT, uid=record.report.run_uid),
        "unmapped": {
            "nessus": {
                "plugin_id": item.plugin_id,
                "plugin_family": item.plugin_family,
                "risk_factor": item.risk_factor,
                "port": item.port,
                "protocol": item.protocol,
                "service": item.service,
                "solution": item.solution,
                "plugin_output_sha256": item.plugin_output_sha256,
                "plugin_output_size": item.plugin_output_size,
                "truncated": item.truncated,
                "output_bounded": item.output_bounded,
                "history_id": record.report.history_id,
                "history_status": record.report.history_status,
                "archived": record.report.archived,
                "source": record.report.source,
            }
        },
    }


def map_finding(record: NessusFindingRecord, ctx: MapContext) -> list[Any]:
    """Severity 1-4 -> OCSF 2002; severity 0 -> OCSF 2004. Compliance items are excluded."""
    if is_compliance(record.item.model_dump()):
        return []
    base = _base(record, ctx)
    item = record.item
    if (item.severity or 0) == 0 or not (item.cves or item.cwes):
        # The shared Vulnerability model requires a CVE or CWE; plugins with neither
        # are detection findings with the evidence preserved in unmapped.
        if (item.severity or 0) != 0:
            return [
                ocsf.DetectionFinding(
                    **base,
                    message=item.synopsis or item.plugin_name,
                    remediation=ocsf.Remediation(desc=item.solution) if item.solution else None,
                )
            ]
        return [
            ocsf.DetectionFinding(
                **base,
                message=item.synopsis or item.plugin_name,
                remediation=ocsf.Remediation(desc=item.solution) if item.solution else None,
            )
        ]
    return [
        ocsf.VulnerabilityFinding(
            **base,
            vulnerabilities=[_vulnerability(item.model_dump())],
        )
    ]


def map_compliance(record: NessusFindingRecord, ctx: MapContext) -> list[Any]:
    """Verified audit checks -> OCSF 2003 keyed by run, host, plugin, and check."""
    if not is_compliance(record.item.model_dump()):
        return []
    base = _base(record, ctx)
    item = record.item
    check_name = item.compliance.get("check_name") or item.plugin_name or item.plugin_id
    result = item.compliance.get("result") or "unknown"
    reference = item.compliance.get("reference")
    check_uid = f"{record.report.run_uid}:{record.host.key}:{item.plugin_id}:{check_name}"
    return [
        ocsf.ComplianceFinding(
            **base,
            compliance=ocsf.Compliance(
                status=result,
                control=check_name,
                standards=[reference] if reference else [],
                checks=[ocsf.Check(uid=check_uid, name=check_name, status=result)],
            ),
            remediation=ocsf.Remediation(desc=item.solution) if item.solution else None,
        )
    ]
