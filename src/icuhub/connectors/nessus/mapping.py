"""Nessus raw-record to OCSF mapping (native severity preserved; no CVSS recomputation)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from icuhub.connectors.nessus.models import NessusFindingRecord
from icuhub.kit.types import MapContext
from icuhub_schemas import ocsf

__all__ = ["event_uid", "is_compliance", "map_compliance", "map_finding"]

_SEVERITY_ID = {0: 1, 1: 2, 2: 3, 3: 4, 4: 5}
_SEVERITY_LABEL = {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
_PRODUCT = ocsf.Product(name="Nessus", vendor_name="Tenable")
# Versions the identity basis. Bump only with a deliberate identity migration.
NESSUS_IDENTITY_VERSION = "nessus-identity/1"


def event_uid(scope: str, host: dict[str, Any], item: dict[str, Any]) -> str:
    """Return the identity digest of one finding: scan scope, host key, plugin, port, and protocol.

    The digest is independent of the export file bytes and document order, so repeated
    exports of one scan yield the same identity.

    Dedupe invariant: items sharing all five fields are one finding. An exact duplicate
    occurrence in a single export collapses into one record by design. A genuinely distinct
    occurrence that shares those fields (for example, one plugin reporting twice on one port)
    is indistinguishable in the export and is not disambiguated.
    """
    basis = json.dumps(
        [NESSUS_IDENTITY_VERSION, scope, host["key"], item["plugin_id"], item.get("port"), item.get("protocol")],
        separators=(",", ":"),
    )
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
    # The shared Vulnerability model accepts exactly one of advisory, cve, or cwe. CVE takes
    # precedence over CWE; the CWE and additional CVEs stay in unmapped.nessus (see _base).
    # A plugin with neither identifier is an advisory keyed by its stable plugin id.
    cves = item.get("cves") or []
    cwes = item.get("cwes") or []
    references = list(item.get("references") or [])
    advisory = cve = cwe = None
    if cves:
        cve = ocsf.Cve(uid=cves[0])
    elif cwes:
        cwe = ocsf.Cwe(uid=cwes[0] if str(cwes[0]).startswith("CWE-") else f"CWE-{cwes[0]}")
    else:
        advisory = ocsf.Advisory(
            uid=f"nessus-plugin:{item['plugin_id']}",
            title=item.get("plugin_name"),
            desc=item.get("synopsis"),
            references=references or None,
        )
    return ocsf.Vulnerability(
        desc=item.get("description") or item.get("synopsis"),
        advisory=advisory,
        cve=cve,
        cwe=cwe,
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
            # sync reads this explicit fingerprint; it must match fp_[0-9a-f]{64}.
            "icuhub": {"fingerprint": f"fp_{record.event_uid}"},
            "nessus": {
                "cves": list(item.cves),
                "cwes": list(item.cwes),
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
    if (item.severity or 0) == 0:
        return [
            ocsf.DetectionFinding(
                **base,
                message=item.synopsis or item.plugin_name,
                remediation=ocsf.Remediation(desc=item.solution) if item.solution else None,
            )
        ]
    # Severity 1-4 items are vulnerabilities; without a CVE or CWE they are advisories.
    return [
        ocsf.VulnerabilityFinding(
            **base,
            vulnerabilities=[_vulnerability(item.model_dump())],
        )
    ]


def map_compliance(record: NessusFindingRecord, ctx: MapContext) -> list[Any]:
    """Verified audit checks -> OCSF 2003 keyed by finding identity and check name."""
    if not is_compliance(record.item.model_dump()):
        return []
    base = _base(record, ctx)
    item = record.item
    check_name = item.compliance.get("check_name") or item.plugin_name or item.plugin_id
    result = item.compliance.get("result") or "unknown"
    reference = item.compliance.get("reference")
    # The raw event UID identifies the plugin occurrence. Finding and fingerprint identity must
    # also include the check so two checks reported by that plugin cannot collapse in sync.
    check_uid = f"{record.event_uid}:{check_name}"
    finding_uid = hashlib.sha256(check_uid.encode("utf-8")).hexdigest()
    base["finding_info"] = base["finding_info"].model_copy(update={"uid": finding_uid})
    base["unmapped"]["icuhub"]["fingerprint"] = f"fp_{finding_uid}"
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
