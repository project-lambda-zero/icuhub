"""Pure Mend SCA vendor-record to OCSF and source-record mapping for Platform 3.0 and SCA 2.0.

Each mapper takes one vendor record and a ``MapContext`` and returns a list of records. Keys
prefixed with an underscore are injected by the connector, never sent by Mend: ``_organization``
(the Mend organization identifier, required on every record), ``_stale_after_days`` (required on
project records), ``_access`` (``"denied"`` when the credential cannot evaluate a project), and
``_report_sha256`` plus ``_schema`` (required and optional report identity on report records).
Vendor key paths follow the Platform 3.0 and SCA 2.0 OpenAPI component names; they remain
unverified until recorded live fixtures exist.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, TypeVar, cast

from pydantic import BaseModel

from icuhub.kit.errors import VendorContractError
from icuhub.kit.mapping import EnumTable, bounded_raw, epoch_ms, severity_id_from_label
from icuhub.kit.types import MapContext, SourceRecord
from icuhub_schemas.ocsf import (
    AffectedCode,
    AffectedPackage,
    CheckStatusId,
    Cloud,
    Compliance,
    ComplianceFinding,
    Cve,
    Cvss,
    File,
    FileTypeId,
    FindingActivityId,
    FindingInfo,
    FindingStatusId,
    Metadata,
    Product,
    ResourceDetails,
    SeverityId,
    Vulnerability,
    VulnerabilityFinding,
    validate_ocsf,
)

__all__ = [
    "FINGERPRINT_ALGORITHM",
    "map_activity",
    "map_legal_alert",
    "map_legal_violation",
    "map_library",
    "map_project",
    "map_report_finding",
    "map_security_alert",
    "map_security_finding",
]

FINGERPRINT_ALGORITHM = "mend-sca-fingerprint/1"

_MEND_VENDOR = "Mend"
_PRODUCT_PLATFORM = "Mend Platform API 3.0"
_PRODUCT_SCA = "Mend SCA API 2.0"
_PRODUCT_REPORT = "Mend Offline Report"
_CLOUD_PROVIDER = "mend_sca"
_VULNERABILITY_CLASS_UID = 2002
_COMPLIANCE_CLASS_UID = 2003
# OCSF activity 1 (Create): each vendor record is an observed finding.
_ACTIVITY_CREATE: Final[FindingActivityId] = 1
# OCSF FileTypeId 1: regular file.
_FILE_TYPE_REGULAR: Final[FileTypeId] = 1
_UNKNOWN_VERSION = "unknown"
_MS_PER_DAY = 86_400_000

_SEVERITY = EnumTable(mapping={"Critical": 5, "High": 4, "Medium": 3, "Low": 2}, default=0)
# OCSF FindingStatusId: 1 New, 3 Suppressed, 4 Resolved, 99 Other. Unrecognized vendor statuses are Other.
_FINDING_STATUS_IDS: Final[dict[str, FindingStatusId]] = {
    "ACTIVE": 1,
    "NEW": 1,
    "IGNORED": 3,
    "RESOLVED": 4,
    "FIXED": 4,
}
_FINDING_STATUS_OTHER: Final[FindingStatusId] = 99
# OCSF CheckStatusId: 2 Fail for an open violation; any other vendor status is Other.
_CHECK_FAIL: Final[CheckStatusId] = 2
_CHECK_OTHER: Final[CheckStatusId] = 99
_OPEN_STATUSES = frozenset({"ACTIVE", "NEW", "OPEN"})
_SCOPE_KINDS = {"ORGANIZATION": "organization", "APPLICATION": "application", "PROJECT": "project"}
_ROLLUP_SEVERITY_KEYS = ("critical", "high", "medium", "low")

_Model = TypeVar("_Model", bound=BaseModel)


@dataclass(frozen=True)
class _ProjectRef:
    """Project identity carried by every project-scoped vendor record."""

    organization: str
    uuid: str
    name: str | None
    path: str | None
    application: str | None

    @property
    def asset_ref(self) -> str:
        """Return the ``project:<mend-org>/<projectUuid>`` asset reference."""
        return f"project:{self.organization}/{self.uuid}"


@dataclass(frozen=True)
class _Component:
    """Package or library coordinates shared by findings, legal violations, and inventory."""

    display_name: str
    group_id: str | None
    artifact_id: str | None
    version: str | None
    kind: str | None
    path: str | None
    dependency_type: str | None
    direct_dependency: bool | None
    library_locations: list[Any]
    purl: str | None
    source_file: str | None
    library_uuid: str | None

    def package_key(self) -> str:
        """Return the PURL when present, otherwise the group:artifact:version coordinates."""
        if self.purl is not None:
            return self.purl
        parts = [part for part in (self.group_id, self.artifact_id or self.display_name, self.version) if part]
        return ":".join(parts)

    def as_dict(self) -> dict[str, Any]:
        """Return the preserved vendor component detail for ``unmapped``."""
        return {
            "name": self.display_name,
            "group_id": self.group_id,
            "artifact_id": self.artifact_id,
            "version": self.version,
            "type": self.kind,
            "path": self.path,
            "dependency_type": self.dependency_type,
            "direct_dependency": self.direct_dependency,
            "library_locations": self.library_locations,
            "purl": self.purl,
            "source_file": self.source_file,
            "library_uuid": self.library_uuid,
        }


def _mapping(parent: Mapping[str, Any], key: str, where: str) -> Mapping[str, Any]:
    value = parent.get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise VendorContractError(f"Mend {where} field {key!r} must be an object")
    return value


def _text(parent: Mapping[str, Any], key: str) -> str | None:
    value = parent.get(key)
    return value if isinstance(value, str) and value else None


def _required_text(parent: Mapping[str, Any], key: str, where: str) -> str:
    value = _text(parent, key)
    if value is None:
        raise VendorContractError(f"Mend {where} is missing {key}")
    return value


def _named(parent: Mapping[str, Any], key: str) -> str | None:
    """Return a string field, or the ``name`` of an object field."""
    value = parent.get(key)
    if isinstance(value, str) and value:
        return value
    if isinstance(value, Mapping):
        return _text(value, "name")
    return None


def _required_named(parent: Mapping[str, Any], key: str, where: str) -> str:
    value = _named(parent, key)
    if value is None:
        raise VendorContractError(f"Mend {where} is missing {key}")
    return value


def _number(parent: Mapping[str, Any], key: str) -> float | None:
    value = parent.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _count(parent: Mapping[str, Any], key: str) -> int | None:
    value = parent.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _bool(parent: Mapping[str, Any], key: str) -> bool | None:
    value = parent.get(key)
    return value if isinstance(value, bool) else None


def _time_ms(parent: Mapping[str, Any], key: str) -> int | None:
    value = parent.get(key)
    return None if value is None else epoch_ms(value)


def _optional_dict(parent: Mapping[str, Any], key: str, where: str) -> dict[str, Any] | None:
    return dict(_mapping(parent, key, where)) or None


def _organization(raw: Mapping[str, Any]) -> str:
    return _required_text(raw, "_organization", "record")


def _observed_ms(ctx: MapContext) -> int:
    observed = epoch_ms(ctx.received_at.isoformat())
    if observed is None:
        raise VendorContractError("Mend observation time is unavailable")
    return observed


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path)[-1] or path


def _fingerprint(kind: str, values: Mapping[str, str | None]) -> str:
    """Return the SHA-256 fingerprint over the algorithm version, record kind, and identity inputs."""
    payload = {"algorithm": FINGERPRINT_ALGORITHM, "kind": kind, "values": dict(values)}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _vulnerability_fingerprint(project: _ProjectRef, vulnerability_id: str, component: _Component) -> str:
    return _fingerprint(
        "vulnerability",
        {
            "project_uuid": project.uuid,
            "vulnerability": vulnerability_id,
            "package": component.package_key(),
            "dependency_path": component.path,
        },
    )


def _legal_fingerprint(
    project: _ProjectRef,
    policy: str,
    license_name: str | None,
    component: _Component,
) -> str:
    return _fingerprint(
        "legal",
        {
            "project_uuid": project.uuid,
            "policy": policy,
            "license": license_name,
            "package": component.package_key(),
        },
    )


def _checked(model: _Model) -> _Model:
    """Validate the dumped document against the pinned OCSF schema; a violation is a mapper defect."""
    validate_ocsf(model.model_dump(mode="json", exclude_none=True))
    return model


def _project_ref(raw: Mapping[str, Any], organization: str) -> _ProjectRef:
    project = _mapping(raw, "project", "record")
    if not project:
        raise VendorContractError("Mend record is missing project")
    return _ProjectRef(
        organization=organization,
        uuid=_required_text(project, "uuid", "project"),
        name=_text(project, "name"),
        path=_text(project, "path"),
        application=_named(project, "application"),
    )


def _project_resource(project: _ProjectRef) -> ResourceDetails:
    return ResourceDetails(uid=project.asset_ref, name=project.name, type="project", provider=_MEND_VENDOR)


def _component_from(component: Mapping[str, Any]) -> _Component:
    artifact_id = _text(component, "artifactId")
    purl = _text(component, "purl")
    display_name = _text(component, "name") or artifact_id or purl
    if display_name is None:
        raise VendorContractError("Mend component has no name, artifactId, or purl")
    locations = component.get("libraryLocations") or []
    if not isinstance(locations, list):
        raise VendorContractError("Mend component libraryLocations must be a list")
    return _Component(
        display_name=display_name,
        group_id=_text(component, "groupId"),
        artifact_id=artifact_id,
        version=_text(component, "version"),
        kind=_text(component, "type"),
        path=_text(component, "path"),
        dependency_type=_text(component, "dependencyType"),
        direct_dependency=_bool(component, "directDependency"),
        library_locations=list(locations),
        purl=purl,
        source_file=_text(component, "sourceFile"),
        library_uuid=_text(component, "uuid"),
    )


def _severity_label(parent: Mapping[str, Any]) -> str | None:
    label = _text(parent, "severity")
    return label.capitalize() if label is not None else None


def _finding_status_id(status: str | None) -> FindingStatusId | None:
    if status is None:
        return None
    return _FINDING_STATUS_IDS.get(status.upper(), _FINDING_STATUS_OTHER)


def _violation_check_status_id(status: str | None) -> CheckStatusId:
    if status is None or status.upper() in _OPEN_STATUSES:
        return _CHECK_FAIL
    return _CHECK_OTHER


def _cvss_version(kind: str | None, vector: str | None) -> str | None:
    if vector is not None and vector.startswith("CVSS:"):
        return vector.split("/", 1)[0][len("CVSS:") :]
    if kind == "CVSS_2":
        return "2.0"
    return None


def _cvss(vulnerability: Mapping[str, Any]) -> tuple[list[Cvss], list[dict[str, Any]]]:
    """Split CVSS_2 and CVSS_3 entries into typed OCSF scores plus the full vendor detail."""
    entries = vulnerability.get("cvss") or []
    if not isinstance(entries, list):
        raise VendorContractError("Mend vulnerability cvss must be a list")
    scores: list[Cvss] = []
    detail: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise VendorContractError("Mend vulnerability cvss entry must be an object")
        kind = _text(entry, "type")
        vector = _text(entry, "scoreMetadataVector")
        score = _number(entry, "score")
        severity = _text(entry, "severity")
        detail.append(
            {
                "type": kind,
                "score": score,
                "source": _text(entry, "source"),
                "vector": vector,
                "severity": severity,
            }
        )
        version = _cvss_version(kind, vector)
        if score is not None and version is not None:
            scores.append(Cvss(base_score=score, version=version, severity=severity, vector_string=vector))
    return scores, detail


def _risk(vulnerability: Mapping[str, Any]) -> dict[str, Any] | None:
    risk = _mapping(vulnerability, "risk", "vulnerability")
    if not risk:
        return None
    return {"score": _number(risk, "score"), "level": _text(risk, "level")}


def _threat_assessment(vulnerability: Mapping[str, Any]) -> dict[str, Any] | None:
    threat = _mapping(vulnerability, "threatAssessment", "vulnerability")
    if not threat:
        return None
    return {
        "exploit_code_maturity": _text(threat, "exploitCodeMaturity"),
        "epss_percentage": _number(threat, "epssPercentage"),
    }


def _top_fix(vulnerability: Mapping[str, Any]) -> dict[str, Any] | None:
    top_fix = _mapping(vulnerability, "topFix", "vulnerability")
    if not top_fix:
        return None
    return {
        "id": _text(top_fix, "id"),
        "type": _text(top_fix, "type"),
        "origin": _text(top_fix, "origin"),
        "message": _text(top_fix, "message"),
    }


def _vulnerability_finding(
    *,
    uid: str,
    fingerprint: str,
    api_version: str | None,
    product_name: str,
    raw: dict[str, Any],
    ctx: MapContext,
    organization: str,
    project: _ProjectRef,
    info: Mapping[str, Any],
    vulnerability: Mapping[str, Any],
    component: _Component,
    identity: dict[str, Any],
) -> VulnerabilityFinding:
    """Build one OCSF 2002 finding from a normalized vulnerability, component, and status block."""
    vulnerability_id = _required_text(vulnerability, "name", "vulnerability")
    severity_label = _severity_label(vulnerability)
    status_text = _text(info, "findingStatus") or _text(info, "status")
    detected = _time_ms(info, "detectedAt")
    modified = _time_ms(info, "modifiedAt")
    scores, cvss_detail = _cvss(vulnerability)
    top_fix = _top_fix(vulnerability)
    package = AffectedPackage(
        name=component.display_name,
        version=component.version or _UNKNOWN_VERSION,
        type=component.kind,
        purl=component.purl,
        path=component.path,
    )
    affected_code = None
    if component.source_file is not None:
        affected_code = [
            AffectedCode(
                file=File(
                    name=_basename(component.source_file),
                    type_id=_FILE_TYPE_REGULAR,
                    path=component.source_file,
                )
            )
        ]
    cve = Cve(uid=vulnerability_id, desc=_text(vulnerability, "description"), cvss=scores or None)
    return _checked(
        VulnerabilityFinding(
            time=modified or detected or _observed_ms(ctx),
            severity_id=cast(SeverityId, severity_id_from_label(severity_label, _SEVERITY)),
            severity=severity_label,
            activity_id=_ACTIVITY_CREATE,
            type_uid=_VULNERABILITY_CLASS_UID * 100 + _ACTIVITY_CREATE,
            status_id=_finding_status_id(status_text),
            status=status_text,
            finding_info=FindingInfo(
                uid=uid,
                uid_alt=fingerprint,
                title=f"{vulnerability_id} in {component.display_name}",
                modified_time=modified,
                first_seen_time=detected,
                product=Product(name=product_name, vendor_name=_MEND_VENDOR),
            ),
            vulnerabilities=[
                Vulnerability(
                    cve=cve,
                    affected_code=affected_code,
                    affected_packages=[package],
                )
            ],
            metadata=Metadata(product=Product(name=product_name, vendor_name=_MEND_VENDOR), uid=uid),
            resources=[_project_resource(project)],
            cloud=Cloud(provider=_CLOUD_PROVIDER),
            osint=[],
            unmapped={
                "mend_sca": {
                    "api_version": api_version,
                    "organization": organization,
                    "project": {"uuid": project.uuid, "name": project.name, "path": project.path},
                    "application": project.application,
                    "fingerprint": fingerprint,
                    "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
                    "identity": identity,
                    "component": component.as_dict(),
                    "dependency_path": component.path,
                    "vulnerability": {
                        "name": vulnerability_id,
                        "native_severity": _text(vulnerability, "severity"),
                        "publish_date": _time_ms(vulnerability, "publishDate"),
                        "modified_date": _time_ms(vulnerability, "modifiedDate"),
                    },
                    "cvss": cvss_detail,
                    "risk": _risk(vulnerability),
                    "threat_assessment": _threat_assessment(vulnerability),
                    "effective_info": _optional_dict(vulnerability, "effectiveInfo", "vulnerability"),
                    "top_fix": top_fix,
                    "finding_status": _text(info, "findingStatus"),
                    "deprecated_status": _text(info, "status"),
                    "suppression": info.get("suppression"),
                    "comment": _text(info, "comment"),
                }
            },
            raw_data=bounded_raw(raw),
        )
    )


def _compliance_finding(
    *,
    uid: str,
    uid_alt: str | None,
    fingerprint: str,
    api_version: str | None,
    product_name: str,
    raw: dict[str, Any],
    info: Mapping[str, Any],
    ctx: MapContext,
    organization: str,
    project: _ProjectRef,
    component: _Component,
    policy: str,
    license_name: str | None,
    identity: dict[str, Any],
) -> ComplianceFinding:
    """Build one OCSF 2003 compliance finding for a license or policy violation."""
    severity_label = _severity_label(info) or _severity_label(raw)
    status_text = _text(info, "findingStatus") or _text(info, "status")
    detected = _time_ms(info, "detectedAt")
    modified = _time_ms(info, "modifiedAt")
    return _checked(
        ComplianceFinding(
            class_uid=_COMPLIANCE_CLASS_UID,
            activity_id=_ACTIVITY_CREATE,
            type_uid=_COMPLIANCE_CLASS_UID * 100 + _ACTIVITY_CREATE,
            time=modified or detected or _observed_ms(ctx),
            severity_id=cast(SeverityId, severity_id_from_label(severity_label, _SEVERITY)),
            severity=severity_label,
            status_id=_finding_status_id(status_text),
            status=status_text,
            finding_info=FindingInfo(
                uid=uid,
                uid_alt=uid_alt,
                title=f"{policy} in {component.display_name}",
                modified_time=modified,
                first_seen_time=detected,
                product=Product(name=product_name, vendor_name=_MEND_VENDOR),
            ),
            compliance=Compliance(
                status=status_text or "Violating",
                status_id=_violation_check_status_id(status_text),
                control=policy,
            ),
            metadata=Metadata(product=Product(name=product_name, vendor_name=_MEND_VENDOR), uid=uid),
            resources=[_project_resource(project)],
            cloud=Cloud(provider=_CLOUD_PROVIDER),
            osint=[],
            unmapped={
                "mend_sca": {
                    "api_version": api_version,
                    "organization": organization,
                    "project": {"uuid": project.uuid, "name": project.name, "path": project.path},
                    "application": project.application,
                    "fingerprint": fingerprint,
                    "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
                    "identity": identity,
                    "policy": policy,
                    "license": license_name,
                    "component": component.as_dict(),
                    "finding_status": _text(info, "findingStatus"),
                    "deprecated_status": _text(info, "status"),
                    "comment": _text(info, "comment"),
                }
            },
            raw_data=bounded_raw(raw),
        )
    )


def map_security_finding(raw: dict[str, Any], ctx: MapContext) -> list[VulnerabilityFinding]:
    """Map one Platform 3.0 security finding to an OCSF 2002 finding keyed by its finding UUID."""
    organization = _organization(raw)
    info = _mapping(raw, "findingInfo", "finding")
    # Paged v3 findings carry the identity at the top level; findingInfo holds status only.
    finding_uuid = _required_text(raw, "uuid", "finding")
    project = _project_ref(raw, organization)
    component = _component_from(_mapping(raw, "component", "finding"))
    vulnerability = _mapping(raw, "vulnerability", "finding")
    fingerprint = _vulnerability_fingerprint(
        project, _required_text(vulnerability, "name", "vulnerability"), component
    )
    return [
        _vulnerability_finding(
            uid=f"mend_sca:{organization}:finding:{finding_uuid}",
            fingerprint=fingerprint,
            api_version="3.0",
            product_name=_PRODUCT_PLATFORM,
            raw=raw,
            ctx=ctx,
            organization=organization,
            project=project,
            info=info,
            vulnerability=vulnerability,
            component=component,
            identity={"finding_uuid": finding_uuid},
        )
    ]


def map_security_alert(raw: dict[str, Any], ctx: MapContext) -> list[VulnerabilityFinding]:
    """Map one SCA 2.0 security alert to an OCSF 2002 finding keyed by its alert UUID."""
    organization = _organization(raw)
    info = _mapping(raw, "alertInfo", "alert")
    # SCA 2.0 alerts carry the identity at the top level; alertInfo holds status and timestamps.
    alert_uuid = _required_text(raw, "uuid", "alert")
    project = _project_ref(raw, organization)
    component = _component_from(_mapping(raw, "component", "alert") or _mapping(raw, "library", "alert"))
    vulnerability = _mapping(raw, "vulnerability", "alert")
    fingerprint = _vulnerability_fingerprint(
        project, _required_text(vulnerability, "name", "vulnerability"), component
    )
    return [
        _vulnerability_finding(
            uid=f"mend_sca:{organization}:alert:{alert_uuid}",
            fingerprint=fingerprint,
            api_version="2.0",
            product_name=_PRODUCT_SCA,
            raw=raw,
            ctx=ctx,
            organization=organization,
            project=project,
            info=info,
            vulnerability=vulnerability,
            component=component,
            identity={"alert_uuid": alert_uuid},
        )
    ]


def map_legal_violation(raw: dict[str, Any], ctx: MapContext) -> list[ComplianceFinding]:
    """Map one Platform 3.0 legal violation to an OCSF 2003 compliance finding keyed by its fingerprint."""
    organization = _organization(raw)
    project = _project_ref(raw, organization)
    component = _component_from(_mapping(raw, "component", "legal violation"))
    policy = _required_named(raw, "policy", "legal violation")
    license_name = _named(raw, "license")
    fingerprint = _legal_fingerprint(project, policy, license_name, component)
    return [
        _compliance_finding(
            uid=f"mend_sca:{organization}:legal_violation:{fingerprint}",
            uid_alt=None,
            fingerprint=fingerprint,
            api_version="3.0",
            product_name=_PRODUCT_PLATFORM,
            raw=raw,
            info=raw,
            ctx=ctx,
            organization=organization,
            project=project,
            component=component,
            policy=policy,
            license_name=license_name,
            identity={},
        )
    ]


def map_legal_alert(raw: dict[str, Any], ctx: MapContext) -> list[ComplianceFinding]:
    """Map one SCA 2.0 legal alert to an OCSF 2003 compliance finding keyed by its alert UUID."""
    organization = _organization(raw)
    info = _mapping(raw, "alertInfo", "legal alert")
    # SCA 2.0 legal alerts carry the identity at the top level and no policy object; the license
    # is the policy identity the alert is raised against.
    alert_uuid = _required_text(raw, "uuid", "legal alert")
    project = _project_ref(raw, organization)
    component = _component_from(_mapping(raw, "component", "legal alert") or _mapping(raw, "library", "legal alert"))
    license_name = _named(raw, "license")
    policy = _named(raw, "policy") or license_name
    if policy is None:
        raise VendorContractError("Mend legal alert is missing policy and license")
    fingerprint = _legal_fingerprint(project, policy, license_name, component)
    return [
        _compliance_finding(
            uid=f"mend_sca:{organization}:legal_alert:{alert_uuid}",
            uid_alt=fingerprint,
            fingerprint=fingerprint,
            api_version="2.0",
            product_name=_PRODUCT_SCA,
            raw=raw,
            info=info,
            ctx=ctx,
            organization=organization,
            project=project,
            component=component,
            policy=policy,
            license_name=license_name,
            identity={"alert_uuid": alert_uuid},
        )
    ]


def map_report_finding(raw: dict[str, Any], ctx: MapContext) -> list[VulnerabilityFinding]:
    """Map one offline report record to an OCSF 2002 finding keyed by report SHA-256 and fingerprint.

    Input is the flat ``{"schema", "key", "fields"}`` row produced by ``reports.py``. Reports carry no
    project UUID, so the fingerprint identity is the project name plus the package coordinates.
    Suppressed rows keep their vendor status (ignored or resolved) rather than being dropped.
    """
    organization = _organization(raw)
    report_sha = _required_text(raw, "_report_sha256", "report record")
    schema = _required_text(raw, "schema", "report record")
    record_key = _required_text(raw, "key", "report record")
    fields = _mapping(raw, "fields", "report record")
    vulnerability_id = _required_text(fields, "vulnerability_id", "report fields")
    suppressed = _bool(fields, "suppressed")
    if suppressed is None:
        raise VendorContractError("report fields.suppressed must be a boolean")
    path_parts = fields.get("dependency_path") or []
    if not isinstance(path_parts, list) or not all(isinstance(part, str) for part in path_parts):
        raise VendorContractError("report fields.dependency_path must be a list of strings")
    dependency_path = "/".join(path_parts) or None
    library_name = _text(fields, "library_name")
    library_version = _text(fields, "library_version")
    library_purl = _text(fields, "library_purl")
    library_sha1 = _text(fields, "library_sha1")
    project_name = _text(fields, "project_name")
    severity_label = _severity_label(fields)
    status_text = _text(fields, "suppression_reason") if suppressed else "ACTIVE"
    fingerprint = _fingerprint(
        "report_vulnerability",
        {
            "project_name": project_name,
            "vulnerability": vulnerability_id,
            "library_name": library_name,
            "library_version": library_version,
            "library_purl": library_purl,
            "library_sha1": library_sha1,
            "dependency_path": dependency_path,
        },
    )
    cvss_score = _number(fields, "cvss_score")
    cvss_vector = _text(fields, "cvss_vector")
    scores = None
    if cvss_score is not None:
        version = _cvss_version(None, cvss_vector) or _UNKNOWN_VERSION
        scores = [Cvss(base_score=cvss_score, version=version, vector_string=cvss_vector)]
    cve = Cve(uid=vulnerability_id, desc=_text(fields, "description"), cvss=scores)
    package = (
        AffectedPackage(name=library_name, version=library_version or _UNKNOWN_VERSION, purl=library_purl)
        if library_name is not None
        else None
    )
    uid = f"mend_sca:{organization}:report:{report_sha}:{fingerprint}"
    title = f"{vulnerability_id} in {library_name}" if library_name is not None else vulnerability_id
    return [
        _checked(
            VulnerabilityFinding(
                time=_observed_ms(ctx),
                severity_id=cast(SeverityId, severity_id_from_label(severity_label, _SEVERITY)),
                severity=severity_label,
                activity_id=_ACTIVITY_CREATE,
                type_uid=_VULNERABILITY_CLASS_UID * 100 + _ACTIVITY_CREATE,
                status_id=_finding_status_id(status_text),
                status=status_text,
                finding_info=FindingInfo(
                    uid=uid,
                    uid_alt=fingerprint,
                    title=title,
                    product=Product(name=_PRODUCT_REPORT, vendor_name=_MEND_VENDOR),
                ),
                vulnerabilities=[Vulnerability(cve=cve, affected_packages=[package] if package else None)],
                metadata=Metadata(product=Product(name=_PRODUCT_REPORT, vendor_name=_MEND_VENDOR), uid=uid),
                cloud=Cloud(provider=_CLOUD_PROVIDER),
                osint=[],
                unmapped={
                    "mend_sca": {
                        "organization": organization,
                        "report": {"sha256": report_sha, "schema": schema, "record_key": record_key},
                        "project_name": project_name,
                        "fingerprint": fingerprint,
                        "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
                        "component": {
                            "name": library_name,
                            "version": library_version,
                            "purl": library_purl,
                            "sha1": library_sha1,
                            "dependency_path": dependency_path,
                            "source_file": _text(fields, "source_file"),
                        },
                        "vulnerability": {
                            "name": vulnerability_id,
                            "native_severity": severity_label,
                            "published_at": _text(fields, "published_at"),
                            "modified_at": _text(fields, "modified_at"),
                        },
                        "fix_resolution": _text(fields, "fix_resolution"),
                        "suppressed": suppressed,
                        "suppression_reason": _text(fields, "suppression_reason"),
                    }
                },
                raw_data=bounded_raw(raw),
            )
        )
    ]


def map_library(raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
    """Map one Platform 3.0 library to a non-finding inventory record keyed by library UUID."""
    del ctx
    organization = _organization(raw)
    library_uuid = _required_text(raw, "uuid", "library")
    project = _project_ref(raw, organization)
    component = _component_from(raw)
    fingerprint = _fingerprint(
        "library",
        {
            "project_uuid": project.uuid,
            "package": component.package_key(),
            "version": component.version,
            "type": component.kind,
        },
    )
    return [
        SourceRecord(
            record_type="library",
            uid=f"mend_sca:{organization}:library:{project.uuid}:{library_uuid}",
            revision=component.version,
            data={
                "organization": organization,
                "asset_ref": project.asset_ref,
                "application": project.application,
                "project_uuid": project.uuid,
                "project_name": project.name,
                "project_path": project.path,
                "name": component.display_name,
                "group_id": component.group_id,
                "artifact_id": component.artifact_id,
                "version": component.version,
                "type": component.kind,
                "purl": component.purl,
                "path": component.path,
                "library_locations": component.library_locations,
                "fingerprint": fingerprint,
                "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
                "raw_data": bounded_raw(raw),
            },
        )
    ]


def map_activity(raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
    """Map one Platform 3.0 activity event to a non-finding audit record keyed by event UUID."""
    del ctx
    organization = _organization(raw)
    event_uuid = _required_text(raw, "uuid", "activity event")
    occurred_at = _time_ms(raw, "timestamp")
    if occurred_at is None:
        raise VendorContractError("Mend activity event is missing timestamp")
    scope = _mapping(raw, "scope", "activity event")
    scope_type = _text(scope, "type")
    scope_uuid = _text(scope, "uuid")
    scope_kind = _SCOPE_KINDS.get(scope_type) if scope_type is not None else None
    asset_ref = f"{scope_kind}:{organization}/{scope_uuid}" if scope_kind and scope_uuid else None
    return [
        SourceRecord(
            record_type="audit_event",
            uid=f"mend_sca:{organization}:activity:{event_uuid}",
            revision=None,
            data={
                "organization": organization,
                "event_type": _text(raw, "type"),
                "occurred_at": occurred_at,
                "actor": _named(raw, "user"),
                "scope_type": scope_type,
                "scope_uuid": scope_uuid,
                "asset_ref": asset_ref,
                "raw_data": bounded_raw(raw),
            },
        )
    ]


def _rollup(summary: Mapping[str, Any]) -> dict[str, Any]:
    findings = _mapping(summary, "findings", "project summary")
    libraries = _mapping(summary, "libraries", "project summary")
    legal = _mapping(summary, "legalViolations", "project summary")
    return {
        "findings": {
            "total": _count(findings, "total"),
            **{key: _count(findings, key) for key in _ROLLUP_SEVERITY_KEYS},
        },
        "libraries": {
            "total": _count(libraries, "total"),
            "vulnerable": _count(libraries, "vulnerable"),
        },
        "legal_violations": {"total": _count(legal, "total")},
    }


def _rollup_complete(rollup: Mapping[str, Any]) -> bool:
    values = [
        *rollup["findings"].values(),
        *rollup["libraries"].values(),
        *rollup["legal_violations"].values(),
    ]
    return all(value is not None for value in values)


def map_project(raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
    """Map one project and its summary rollup to a non-finding project record with explicit coverage."""
    organization = _organization(raw)
    project_uuid = _required_text(raw, "uuid", "project")
    stale_after_days = _count(raw, "_stale_after_days")
    if stale_after_days is None or stale_after_days < 1:
        raise VendorContractError("Mend project record is missing a positive _stale_after_days")
    access = _text(raw, "_access")
    if access not in (None, "denied"):
        raise VendorContractError(f"Mend project _access {access!r} is not supported")
    summary = _mapping(raw, "summary", "project")
    rollup = _rollup(summary) if summary else None
    last_scan_at = _time_ms(raw, "lastScanDate")
    now = _observed_ms(ctx)

    if access == "denied":
        scan_state = "denied"
    elif last_scan_at is None:
        scan_state = "never_scanned"
    elif last_scan_at < now - stale_after_days * _MS_PER_DAY:
        scan_state = "stale"
    else:
        scan_state = "current"

    if scan_state in ("denied", "never_scanned") or rollup is None:
        coverage = "not_evaluated"
    elif scan_state == "stale":
        coverage = "partial"
    else:
        coverage = "complete" if _rollup_complete(rollup) else "partial"

    reported_rollup = rollup if scan_state in ("current", "stale") else None
    zero_findings = (
        rollup["findings"]["total"] == 0 if scan_state == "current" and coverage == "complete" and rollup else None
    )
    project_uuid_ref = f"project:{organization}/{project_uuid}"
    return [
        SourceRecord(
            record_type="project",
            uid=f"mend_sca:{organization}:project:{project_uuid}",
            revision=str(last_scan_at) if last_scan_at is not None else None,
            data={
                "organization": organization,
                "project_uuid": project_uuid,
                "asset_ref": project_uuid_ref,
                "name": _text(raw, "name"),
                "path": _text(raw, "path"),
                "application": _named(raw, "application"),
                "scan_state": scan_state,
                "coverage": coverage,
                "last_scan_at": last_scan_at,
                "stale_after_days": stale_after_days,
                "zero_findings": zero_findings,
                "rollup": reported_rollup,
                "raw_data": bounded_raw(raw),
            },
        )
    ]
