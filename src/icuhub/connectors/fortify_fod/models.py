"""Configuration, operation, and action models for Fortify on Demand."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = [
    "ApplicationArgs",
    "BulkAuditInput",
    "CancelScanInput",
    "CreateReportInput",
    "DataExportArgs",
    "DataExportType",
    "DeleteResourceInput",
    "DownloadOutput",
    "FortifyFodConfig",
    "ImportScanInput",
    "IssueArgs",
    "IssueHistoryArgs",
    "IssueInstanceArgs",
    "ListScansArgs",
    "MicroservicesArgs",
    "ReleaseArgs",
    "ReleaseFprArgs",
    "ReportArgs",
    "ScanArgs",
    "ScanProfile",
    "StartScanInput",
    "StrictModel",
    "VendorListOutput",
    "VendorObjectOutput",
]

_DIGITS = r"^[0-9]+$"
_DIGITS_RE = re.compile(_DIGITS)
_SHA256 = r"^[0-9a-f]{64}$"

DataExportType = Literal[
    "IssuesExport",
    "ScansExport",
    "ReleasesExport",
    "ApplicationsExport",
    "EntitlementConsumptionExport",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FortifyFodConfig(ConnectorConfig):
    """OAuth client credentials and explicit destructive-action gate."""

    client_id: str = Field(min_length=1)
    client_secret: SecretRef
    destructive_enabled: bool = False


class VendorObjectOutput(StrictModel):
    record: dict


class VendorListOutput(StrictModel):
    records: list[dict]
    total_count: int = Field(ge=0)


class DownloadOutput(StrictModel):
    ready: bool
    vendor_ref: str
    sha256: str | None = Field(default=None, pattern=_SHA256)
    size_bytes: int = Field(default=0, ge=0)
    content_base64: str | None = None


class ReleaseArgs(StrictModel):
    release_id: str = Field(pattern=_DIGITS)


class ApplicationArgs(StrictModel):
    application_id: str = Field(pattern=_DIGITS)


class MicroservicesArgs(ApplicationArgs):
    pass


class IssueInstanceArgs(ReleaseArgs):
    instance_id: str = Field(min_length=1, max_length=128)


class IssueArgs(ReleaseArgs):
    vuln_id: str = Field(min_length=1, max_length=128)


class IssueHistoryArgs(IssueArgs):
    include_system_events: bool = False


class ListScansArgs(StrictModel):
    release_id: str | None = Field(default=None, pattern=_DIGITS)
    modified_since: datetime | None = None


class ScanArgs(StrictModel):
    scan_id: str = Field(pattern=_DIGITS)


class ReleaseFprArgs(ReleaseArgs):
    scan_type: Literal["Static", "Dynamic", "Mobile", "Monitoring", "Network", "OpenSource", "SASTAviator"]


class ReportArgs(StrictModel):
    report_id: str = Field(pattern=_DIGITS)


class DataExportArgs(StrictModel):
    data_export_id: str = Field(pattern=_DIGITS)
    expected_type: DataExportType | None = None


class BulkAuditInput(BaseModel):
    """One bulk-edit request against a release's vulnerabilities."""

    model_config = ConfigDict(extra="forbid")

    release_id: str = Field(pattern=_DIGITS)
    vulnerability_ids: list[str] = Field(min_length=1)
    user_id: int | None = Field(default=None, gt=0)
    developer_status: str | None = Field(default=None, min_length=1)
    auditor_status: str | None = Field(default=None, min_length=1)
    severity: str | None = Field(default=None, min_length=1)
    comment: str | None = Field(default=None, min_length=1)
    attributes: dict[str, str] | None = None

    @field_validator("vulnerability_ids")
    @classmethod
    def _ids_are_digits(cls, value: list[str]) -> list[str]:
        for vuln_id in value:
            if not _DIGITS_RE.fullmatch(vuln_id):
                raise ValueError(f"vulnerability id {vuln_id!r} must be decimal digits")
        return value

    @model_validator(mode="after")
    def _has_an_update(self) -> BulkAuditInput:
        if all(
            value is None
            for value in (
                self.user_id,
                self.developer_status,
                self.auditor_status,
                self.severity,
                self.comment,
                self.attributes,
            )
        ):
            raise ValueError("bulk audit needs at least one field to change")
        return self


class ScanProfile(StrictModel):
    technology_stack: str = Field(min_length=1, max_length=128)
    language_level: str | None = Field(default=None, min_length=1, max_length=128)
    audit_preference_type: Literal["Manual", "Automated"] = "Manual"
    scan_policy: Literal["Security", "DevOps", "Classic", "FoD_Legacy_"] | None = None


class StartScanInput(ReleaseArgs):
    assessment_type_id: int = Field(gt=0)
    entitlement_id: int = Field(gt=0)
    entitlement_frequency_type: Literal["SingleScan", "Subscription"]
    profile: ScanProfile
    payload_base64: str = Field(min_length=1)
    payload_sha256: str = Field(pattern=_SHA256)
    billable_acknowledged: Literal[True]


class ImportScanInput(ReleaseArgs):
    scan_type: Literal["Static", "Dynamic", "Mobile"] = "Static"
    payload_base64: str = Field(min_length=1)
    payload_sha256: str = Field(pattern=_SHA256)


class CreateReportInput(StrictModel):
    application_id: str = Field(pattern=_DIGITS)
    release_id: str = Field(pattern=_DIGITS)
    report_template_type_id: int = Field(gt=0)
    report_format: Literal["Pdf", "Html"]
    report_name: str = Field(min_length=1, max_length=255)
    notes: str | None = Field(default=None, max_length=4000)


class CancelScanInput(ReleaseArgs):
    scan_id: str = Field(pattern=_DIGITS)
    approval_ref: str = Field(min_length=1)


class DeleteResourceInput(StrictModel):
    resource_type: Literal["release", "application", "report"]
    resource_id: str = Field(pattern=_DIGITS)
    approval_ref: str = Field(min_length=1)
