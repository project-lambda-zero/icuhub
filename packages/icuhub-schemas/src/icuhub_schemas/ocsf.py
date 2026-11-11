"""OCSF 1.9.0 finding and API activity models, validated against the vendored class schemas.

Each model dumps to a document that passes :func:`validate_ocsf`. Attributes absent from the
input stay ``None`` and are omitted from the dump. Attributes the schema requires have no
default. ``class_uid`` and ``category_uid`` are constants of the class; ``type_uid`` is derived
from ``class_uid`` and ``activity_id``. Vendor attributes without a typed field belong in
``unmapped``; unknown attributes are rejected.

The schema's ``anyOf`` and ``oneOf`` constraints are enforced over the modeled attributes only.
Alternatives the models do not represent (``user.account`` and the other unmodeled ``actor`` and
``network_endpoint`` members) cannot be set, so a model never emits a document the schema would
reject.
"""

from collections.abc import Mapping
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from icuhub_schemas._schema_store import SchemaIssue, format_path, schema_issues

__all__ = [
    "OCSF_VERSION",
    "Account",
    "Actor",
    "Advisory",
    "AffectedCode",
    "AffectedPackage",
    "Api",
    "ApiActivity",
    "Application",
    "ApplicationSecurityPostureFinding",
    "Assessment",
    "Check",
    "Cloud",
    "Compliance",
    "ComplianceFinding",
    "Cve",
    "Cvss",
    "Cwe",
    "DataSecurityFinding",
    "DetectionFinding",
    "File",
    "FindingInfo",
    "Group",
    "HttpHeader",
    "HttpRequest",
    "HttpResponse",
    "IncidentFinding",
    "Metadata",
    "NetworkEndpoint",
    "OcsfValidationError",
    "Osint",
    "Product",
    "Remediation",
    "ResourceDetails",
    "Service",
    "Session",
    "Url",
    "User",
    "Vulnerability",
    "VulnerabilityFinding",
    "validate_ocsf",
]

OCSF_VERSION = "1.9.0"

_CLASS_RESOURCES: dict[int, str] = {
    2002: "ocsf/1.9.0/classes/vulnerability_finding.json",
    2003: "ocsf/1.9.0/classes/compliance_finding.json",
    2004: "ocsf/1.9.0/classes/detection_finding.json",
    2005: "ocsf/1.9.0/classes/incident_finding.json",
    2006: "ocsf/1.9.0/classes/data_security_finding.json",
    2007: "ocsf/1.9.0/classes/application_security_posture_finding.json",
    6003: "ocsf/1.9.0/classes/api_activity.json",
}

SeverityId = Literal[0, 1, 2, 3, 4, 5, 6, 99]
FileTypeId = Literal[0, 1, 2, 3, 4, 5, 6, 7, 8, 99]
OsintTypeId = Literal[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 99]
FindingActivityId = Literal[0, 1, 2, 3, 99]
DataActivityId = Literal[0, 1, 2, 3, 4, 99]
FindingStatusId = Literal[0, 1, 2, 3, 4, 5, 6, 99]
IncidentStatusId = Literal[0, 1, 2, 3, 4, 5, 99]
ApiStatusId = Literal[0, 1, 2, 99]
CheckStatusId = Literal[0, 1, 2, 3, 99]


class OcsfValidationError(ValueError):
    """An OCSF document violates the pinned schema or a model constraint."""

    def __init__(self, issues: list[SchemaIssue]) -> None:
        self.issues: tuple[SchemaIssue, ...] = tuple(issues)
        super().__init__("; ".join(f"{issue.path}: {issue.message}" for issue in self.issues))


def validate_ocsf(document: Mapping[str, Any]) -> None:
    """Validate an OCSF 1.9.0 class document against the vendored schema for its ``class_uid``.

    Raises:
        OcsfValidationError: the document is not an object, its ``class_uid`` is unsupported,
            or it violates the schema. ``issues`` lists every violation with its JSON path.
    """

    if not isinstance(document, Mapping):
        raise OcsfValidationError([SchemaIssue("$", "document must be an object")])
    class_uid = document.get("class_uid")
    resource = _CLASS_RESOURCES.get(class_uid) if isinstance(class_uid, int) else None
    if resource is None:
        raise OcsfValidationError([SchemaIssue("$.class_uid", f"unsupported class_uid {class_uid!r}")])
    issues = schema_issues(document, resource)
    if issues:
        raise OcsfValidationError(issues)


class _Model(BaseModel):
    """Base for OCSF objects. Unknown attributes are rejected, never dropped.

    ``ANY_OF`` names the attributes of which at least one must be set, mirroring a schema
    ``anyOf`` of ``required`` alternatives over the modeled attributes.
    """

    model_config = ConfigDict(extra="forbid")

    ANY_OF: ClassVar[tuple[str, ...]] = ()

    @model_validator(mode="after")
    def _require_any_of(self) -> Self:
        if self.ANY_OF and all(getattr(self, name) is None for name in self.ANY_OF):
            raise ValueError(f"at least one of {', '.join(self.ANY_OF)} is required")
        return self


class Product(_Model):
    ANY_OF: ClassVar[tuple[str, ...]] = ("name", "uid")

    name: str | None = None
    uid: str | None = None
    vendor_name: str | None = None
    version: str | None = None
    url_string: str | None = None
    path: str | None = None


class Metadata(_Model):
    product: Product
    version: Literal["1.9.0"] = "1.9.0"
    uid: str | None = None


class Account(_Model):
    ANY_OF: ClassVar[tuple[str, ...]] = ("name", "uid")

    uid: str | None = None
    name: str | None = None
    type: str | None = None


class Cloud(_Model):
    provider: str
    region: str | None = None
    account: Account | None = None


class Osint(_Model):
    type_id: OsintTypeId
    value: str
    type: str | None = None
    desc: str | None = None


class Cvss(_Model):
    base_score: float
    version: str
    severity: str | None = None
    vector_string: str | None = None
    src_url: str | None = None


class Cwe(_Model):
    uid: str
    caption: str | None = None
    src_url: str | None = None


class Cve(_Model):
    uid: str
    title: str | None = None
    desc: str | None = None
    cvss: list[Cvss] | None = None
    cwe: Cwe | None = None


class File(_Model):
    name: str
    type_id: FileTypeId
    uid: str | None = None
    path: str | None = None
    type: str | None = None
    desc: str | None = None


class AffectedCode(_Model):
    file: File
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None


class AffectedPackage(_Model):
    name: str
    version: str
    type: str | None = None
    purl: str | None = None
    cpe_name: str | None = None
    fixed_in_version: str | None = None
    package_manager: str | None = None
    license: str | None = None
    path: str | None = None


class Advisory(_Model):
    """A vendor security advisory identified by a vendor-assigned, stable ``uid``."""

    uid: str
    title: str | None = None
    desc: str | None = None
    src_url: str | None = None
    references: list[str] | None = None


class Vulnerability(_Model):
    desc: str | None = None
    category: str | None = None
    advisory: Advisory | None = None
    cve: Cve | None = None
    cwe: Cwe | None = None
    references: list[str] | None = None
    affected_code: list[AffectedCode] | None = None
    affected_packages: list[AffectedPackage] | None = None

    @model_validator(mode="after")
    def _exactly_one_identifier(self) -> Self:
        set_count = sum(value is not None for value in (self.advisory, self.cve, self.cwe))
        if set_count != 1:
            raise ValueError("exactly one of advisory, cve, or cwe is required")
        return self


class ResourceDetails(_Model):
    ANY_OF: ClassVar[tuple[str, ...]] = ("name", "uid")

    uid: str | None = None
    uid_alt: str | None = None
    name: str | None = None
    type: str | None = None
    region: str | None = None
    zone: str | None = None
    provider: str | None = None
    namespace: str | None = None
    hostname: str | None = None
    ip: str | None = None
    labels: list[str] | None = None


class Remediation(_Model):
    desc: str
    references: list[str] | None = None


class Check(_Model):
    uid: str | None = None
    name: str | None = None
    desc: str | None = None
    version: str | None = None
    severity: str | None = None
    status: str | None = None
    status_id: CheckStatusId | None = None
    standards: list[str] | None = None


class Assessment(_Model):
    ANY_OF: ClassVar[tuple[str, ...]] = ("name", "uid")

    meets_criteria: bool
    uid: str | None = None
    name: str | None = None
    desc: str | None = None
    category: str | None = None


class Compliance(_Model):
    status: str | None = None
    status_id: CheckStatusId | None = None
    status_code: str | None = None
    status_detail: str | None = None
    control: str | None = None
    category: str | None = None
    desc: str | None = None
    standards: list[str] | None = None
    checks: list[Check] | None = None
    assessments: list[Assessment] | None = None


class FindingInfo(_Model):
    uid: str
    uid_alt: str | None = None
    title: str | None = None
    desc: str | None = None
    src_url: str | None = None
    types: list[str] | None = None
    created_time: int | None = None
    modified_time: int | None = None
    first_seen_time: int | None = None
    last_seen_time: int | None = None
    product: Product | None = None


class Application(_Model):
    ANY_OF: ClassVar[tuple[str, ...]] = ("name", "uid")

    name: str | None = None
    uid: str | None = None
    uid_alt: str | None = None
    type: str | None = None
    version: str | None = None
    desc: str | None = None
    hostname: str | None = None
    labels: list[str] | None = None


class Group(_Model):
    ANY_OF: ClassVar[tuple[str, ...]] = ("name", "uid")

    name: str | None = None
    uid: str | None = None
    uid_alt: str | None = None
    uid_numeric: int | None = None
    desc: str | None = None
    domain: str | None = None
    privileges: list[str] | None = None
    type: str | None = None


class User(_Model):
    ANY_OF: ClassVar[tuple[str, ...]] = ("name", "uid")

    uid: str | None = None
    name: str | None = None
    display_name: str | None = None
    domain: str | None = None
    email_addr: str | None = None
    type: str | None = None
    type_id: int | None = None


class Session(_Model):
    uid: str | None = None
    uid_alt: str | None = None


class Actor(_Model):
    ANY_OF: ClassVar[tuple[str, ...]] = ("user", "session", "app_name", "app_uid", "invoked_by")

    user: User | None = None
    session: Session | None = None
    app_name: str | None = None
    app_uid: str | None = None
    invoked_by: str | None = None


class Service(_Model):
    ANY_OF: ClassVar[tuple[str, ...]] = ("name", "uid")

    name: str | None = None
    uid: str | None = None
    version: str | None = None
    labels: list[str] | None = None


class Api(_Model):
    operation: str
    service: Service | None = None
    version: str | None = None


class NetworkEndpoint(_Model):
    ANY_OF: ClassVar[tuple[str, ...]] = ("domain", "hostname", "ip", "name", "svc_name", "uid")

    uid: str | None = None
    name: str | None = None
    ip: str | None = None
    hostname: str | None = None
    domain: str | None = None
    port: int | None = None
    type: str | None = None
    type_id: int | None = None
    svc_name: str | None = None


class Url(_Model):
    ANY_OF: ClassVar[tuple[str, ...]] = ("path", "url_string")

    url_string: str | None = None
    scheme: str | None = None
    hostname: str | None = None
    domain: str | None = None
    path: str | None = None
    port: int | None = None
    query_string: str | None = None


class HttpHeader(_Model):
    name: str
    value: str


class HttpRequest(_Model):
    uid: str | None = None
    http_method: str | None = None
    url: Url | None = None
    user_agent: str | None = None
    version: str | None = None
    referrer: str | None = None
    x_forwarded_for: str | None = None
    length: int | None = None
    http_headers: list[HttpHeader] | None = None


class HttpResponse(_Model):
    code: int
    message: str | None = None
    status: str | None = None
    content_type: str | None = None
    latency: int | None = None
    length: int | None = None
    body_length: int | None = None
    http_headers: list[HttpHeader] | None = None


class _OcsfEvent(_Model):
    """Attributes every OCSF 1.9.0 finding class in this module carries."""

    CLASS_UID: ClassVar[int]

    class_uid: int
    category_uid: int
    type_uid: int
    time: int
    severity_id: SeverityId
    metadata: Metadata
    cloud: Cloud
    osint: list[Osint]
    severity: str | None = None
    message: str | None = None
    status: str | None = None
    status_detail: str | None = None
    raw_data: str | None = None
    unmapped: dict[str, Any] | None = None

    @model_validator(mode="before")
    @classmethod
    def _derive_type_uid(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        activity_id = data.get("activity_id")
        if not isinstance(activity_id, int) or isinstance(activity_id, bool):
            return data
        expected = cls.CLASS_UID * 100 + activity_id
        supplied = data.get("type_uid")
        if supplied is not None and supplied != expected:
            raise ValueError(f"type_uid {supplied} must equal class_uid * 100 + activity_id ({expected})")
        return {**data, "type_uid": expected}

    def to_ocsf(self) -> dict[str, Any]:
        """Return the OCSF document; it always passes :func:`validate_ocsf`."""

        document = self.model_dump(mode="json", exclude_none=True)
        validate_ocsf(document)
        return document

    @classmethod
    def from_ocsf(cls, document: Mapping[str, Any]) -> Self:
        """Validate an OCSF document against the schema, then parse it into this model."""

        validate_ocsf(document)
        try:
            return cls.model_validate(document)
        except ValidationError as error:
            raise OcsfValidationError(
                [SchemaIssue(format_path(list(item["loc"])), item["msg"]) for item in error.errors()]
            ) from error


class VulnerabilityFinding(_OcsfEvent):
    """OCSF 2002 Vulnerability Finding."""

    CLASS_UID: ClassVar[int] = 2002
    class_uid: Literal[2002] = 2002
    category_uid: Literal[2] = 2
    activity_id: FindingActivityId
    status_id: FindingStatusId | None = None
    finding_info: FindingInfo
    vulnerabilities: list[Vulnerability]
    resources: list[ResourceDetails] | None = None
    actor: Actor | None = None
    api: Api | None = None


class ComplianceFinding(_OcsfEvent):
    """OCSF 2003 Compliance Finding."""

    CLASS_UID: ClassVar[int] = 2003
    class_uid: Literal[2003] = 2003
    category_uid: Literal[2] = 2
    activity_id: FindingActivityId
    status_id: FindingStatusId | None = None
    finding_info: FindingInfo
    compliance: Compliance
    remediation: Remediation | None = None
    resources: list[ResourceDetails] | None = None
    actor: Actor | None = None
    api: Api | None = None


class DetectionFinding(_OcsfEvent):
    """OCSF 2004 Detection Finding."""

    CLASS_UID: ClassVar[int] = 2004
    class_uid: Literal[2004] = 2004
    category_uid: Literal[2] = 2
    activity_id: FindingActivityId
    status_id: FindingStatusId | None = None
    finding_info: FindingInfo
    vulnerabilities: list[Vulnerability] | None = None
    remediation: Remediation | None = None
    resources: list[ResourceDetails] | None = None
    actor: Actor | None = None
    api: Api | None = None


class IncidentFinding(_OcsfEvent):
    """OCSF 2005 Incident Finding."""

    CLASS_UID: ClassVar[int] = 2005
    ANY_OF: ClassVar[tuple[str, ...]] = ("assignee", "assignee_group")

    class_uid: Literal[2005] = 2005
    category_uid: Literal[2] = 2
    activity_id: FindingActivityId
    status_id: IncidentStatusId
    finding_info_list: list[FindingInfo]
    desc: str | None = None
    assignee: User | None = None
    assignee_group: Group | None = None
    actor: Actor | None = None
    api: Api | None = None


class DataSecurityFinding(_OcsfEvent):
    """OCSF 2006 Data Security Finding."""

    CLASS_UID: ClassVar[int] = 2006
    class_uid: Literal[2006] = 2006
    category_uid: Literal[2] = 2
    activity_id: DataActivityId
    status_id: FindingStatusId | None = None
    finding_info: FindingInfo
    file: File | None = None
    src_endpoint: NetworkEndpoint | None = None
    dst_endpoint: NetworkEndpoint | None = None
    resources: list[ResourceDetails] | None = None
    actor: Actor | None = None
    api: Api | None = None


class ApplicationSecurityPostureFinding(_OcsfEvent):
    """OCSF 2007 Application Security Posture Finding."""

    CLASS_UID: ClassVar[int] = 2007
    ANY_OF: ClassVar[tuple[str, ...]] = ("application", "compliance", "remediation", "vulnerabilities")

    class_uid: Literal[2007] = 2007
    category_uid: Literal[2] = 2
    activity_id: FindingActivityId
    status_id: FindingStatusId | None = None
    finding_info: FindingInfo
    application: Application | None = None
    compliance: Compliance | None = None
    remediation: Remediation | None = None
    vulnerabilities: list[Vulnerability] | None = None
    resources: list[ResourceDetails] | None = None
    actor: Actor | None = None
    api: Api | None = None


class ApiActivity(_OcsfEvent):
    """OCSF 6003 API Activity."""

    CLASS_UID: ClassVar[int] = 6003
    class_uid: Literal[6003] = 6003
    category_uid: Literal[6] = 6
    activity_id: DataActivityId
    status_id: ApiStatusId | None = None
    actor: Actor
    api: Api
    src_endpoint: NetworkEndpoint
    dst_endpoint: NetworkEndpoint | None = None
    http_request: HttpRequest | None = None
    http_response: HttpResponse | None = None
    resources: list[ResourceDetails] | None = None
