"""SARIF 2.1.0 models with schema-validated parsing, and conversion from code-located OCSF findings.

Models forbid attributes they do not declare, so a SARIF document using a property outside
this subset is rejected rather than silently losing data. Output from :func:`dump_sarif` and
:func:`findings_to_sarif` is validated against the vendored SARIF 2.1.0 schema.
"""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from icuhub_schemas._schema_store import SchemaIssue, format_path, schema_issues
from icuhub_schemas.ocsf import (
    ApplicationSecurityPostureFinding,
    DetectionFinding,
    Vulnerability,
    VulnerabilityFinding,
)

__all__ = [
    "ArtifactLocation",
    "FindingsConversion",
    "Location",
    "Message",
    "PhysicalLocation",
    "PropertyBag",
    "Region",
    "ReportingConfiguration",
    "ReportingDescriptor",
    "Result",
    "Run",
    "SARIF_VERSION",
    "SarifLog",
    "SarifValidationError",
    "Tool",
    "ToolComponent",
    "dump_sarif",
    "findings_to_sarif",
    "parse_sarif",
]

SARIF_VERSION = "2.1.0"
_SARIF_RESOURCE = "sarif/sarif-schema-2.1.0.json"

ResultLevel = Literal["none", "note", "warning", "error"]
ColumnKind = Literal["utf16CodeUnits", "unicodeCodePoints"]


class SarifValidationError(ValueError):
    """A SARIF document violates the SARIF 2.1.0 schema or a model constraint."""

    def __init__(self, issues: list[SchemaIssue]) -> None:
        self.issues: tuple[SchemaIssue, ...] = tuple(issues)
        super().__init__("; ".join(f"{issue.path}: {issue.message}" for issue in self.issues))


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Message(_Model):
    text: str | None = None
    id: str | None = None


class ArtifactLocation(_Model):
    uri: str | None = None
    uri_base_id: str | None = Field(default=None, alias="uriBaseId")


class Region(_Model):
    start_line: int | None = Field(default=None, alias="startLine", ge=1)
    start_column: int | None = Field(default=None, alias="startColumn", ge=1)
    end_line: int | None = Field(default=None, alias="endLine", ge=1)
    end_column: int | None = Field(default=None, alias="endColumn", ge=1)


class PhysicalLocation(_Model):
    artifact_location: ArtifactLocation | None = Field(default=None, alias="artifactLocation")
    region: Region | None = None


class Location(_Model):
    physical_location: PhysicalLocation | None = Field(default=None, alias="physicalLocation")
    message: Message | None = None


class PropertyBag(_Model):
    """SARIF property bag: an open map of string-keyed values (``security-severity`` lives here)."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class Result(_Model):
    rule_id: str | None = Field(default=None, alias="ruleId")
    rule_index: int | None = Field(default=None, alias="ruleIndex", ge=-1)
    level: ResultLevel | None = None
    rank: float | None = Field(default=None, ge=-1, le=100)
    message: Message
    locations: list[Location] | None = None
    partial_fingerprints: dict[str, str] | None = Field(default=None, alias="partialFingerprints")
    properties: PropertyBag | None = None


class ReportingConfiguration(_Model):
    level: ResultLevel | None = None
    rank: float | None = Field(default=None, ge=-1, le=100)
    enabled: bool | None = None
    properties: PropertyBag | None = None


class ReportingDescriptor(_Model):
    id: str
    name: str | None = None
    short_description: Message | None = Field(default=None, alias="shortDescription")
    full_description: Message | None = Field(default=None, alias="fullDescription")
    help_uri: str | None = Field(default=None, alias="helpUri")
    default_configuration: ReportingConfiguration | None = Field(default=None, alias="defaultConfiguration")
    properties: PropertyBag | None = None


class ToolComponent(_Model):
    name: str
    version: str | None = None
    semantic_version: str | None = Field(default=None, alias="semanticVersion")
    information_uri: str | None = Field(default=None, alias="informationUri")
    rules: list[ReportingDescriptor] | None = None


class Tool(_Model):
    driver: ToolComponent


class Run(_Model):
    tool: Tool
    results: list[Result] | None = None
    column_kind: ColumnKind | None = Field(default=None, alias="columnKind")


class SarifLog(_Model):
    version: Literal["2.1.0"] = "2.1.0"
    schema_uri: str | None = Field(default=None, alias="$schema")
    runs: list[Run]


def _validate(document: Any) -> None:
    issues = schema_issues(document, _SARIF_RESOURCE)
    if issues:
        raise SarifValidationError(issues)


def parse_sarif(data: bytes | str | Mapping[str, Any]) -> SarifLog:
    """Parse a SARIF 2.1.0 document from JSON text, bytes, or an already decoded mapping.

    Raises:
        SarifValidationError: the input is not JSON, violates the schema, or uses a property
            outside the modeled subset.
    """

    if isinstance(data, bytes | str):
        try:
            document = json.loads(data)
        except json.JSONDecodeError as error:
            raise SarifValidationError([SchemaIssue("$", f"invalid JSON: {error.msg}")]) from error
    else:
        document = dict(data)
    _validate(document)
    try:
        return SarifLog.model_validate(document)
    except ValidationError as error:
        raise SarifValidationError(
            [SchemaIssue(format_path(list(item["loc"])), item["msg"]) for item in error.errors()]
        ) from error


def dump_sarif(log: SarifLog) -> dict[str, Any]:
    """Return the SARIF document for a log; the output always passes the SARIF schema."""

    document = log.model_dump(mode="json", by_alias=True, exclude_none=True)
    _validate(document)
    return document


CodeCapableFinding = VulnerabilityFinding | DetectionFinding | ApplicationSecurityPostureFinding


@dataclass(frozen=True)
class FindingsConversion:
    """Result of :func:`findings_to_sarif`.

    ``log`` holds one SARIF result per vulnerability that has at least one code location.
    ``skipped`` lists the input findings that produced no result: they have no
    ``affected_code`` entry with a ``file.path``, or their class carries no vulnerabilities.
    """

    log: SarifLog
    skipped: tuple[CodeCapableFinding, ...]


def _level(severity_id: int) -> ResultLevel:
    if severity_id in (2, 1):
        return "note"
    if severity_id in (4, 5, 6):
        return "error"
    return "warning"


def _rule_id(vulnerability: Vulnerability) -> str:
    # Vulnerability guarantees exactly one of cve or cwe.
    return vulnerability.cve.uid if vulnerability.cve is not None else vulnerability.cwe.uid


def _region(affected: Any) -> Region | None:
    if affected.start_line is None:
        return None
    return Region(
        startLine=affected.start_line,
        startColumn=affected.start_column,
        endLine=affected.end_line,
        endColumn=affected.end_column,
    )


def findings_to_sarif(
    findings: Sequence[CodeCapableFinding],
    tool_name: str,
    tool_version: str | None = None,
) -> FindingsConversion:
    """Convert OCSF findings that point at source code into SARIF results.

    Each vulnerability with at least one ``affected_code`` entry carrying ``file.path``
    becomes one result; every such entry becomes a location on that result. The rule id is
    the CVE id, else the CWE id (the schema requires exactly one). Findings whose classes carry no
    vulnerabilities, or whose vulnerabilities have no code location, are returned in
    ``skipped`` and do not appear in the log.
    """

    results: list[Result] = []
    skipped: list[CodeCapableFinding] = []
    for finding in findings:
        produced = False
        for vulnerability in finding.vulnerabilities or []:
            locations = [
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(uri=affected.file.path),
                        region=_region(affected),
                    )
                )
                for affected in vulnerability.affected_code or []
                if affected.file.path is not None
            ]
            if not locations:
                continue
            produced = True
            message_text = finding.finding_info.title or vulnerability.desc or finding.finding_info.uid
            results.append(
                Result(
                    ruleId=_rule_id(vulnerability),
                    level=_level(finding.severity_id),
                    message=Message(text=message_text),
                    locations=locations,
                )
            )
        if not produced:
            skipped.append(finding)

    driver = ToolComponent(name=tool_name, version=tool_version)
    log = SarifLog(runs=[Run(tool=Tool(driver=driver), results=results)])
    dump_sarif(log)
    return FindingsConversion(log=log, skipped=tuple(skipped))
