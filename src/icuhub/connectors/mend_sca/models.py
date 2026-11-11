"""Typed configuration, cursor, operation, report, and action contracts for Mend SCA."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from icuhub.kit._urls import normalize_base_url
from icuhub.kit.cursors import SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import ConfigError
from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = [
    "DownloadReportArgs",
    "FindingRefArgs",
    "GetPermissionsArgs",
    "GetPolicyArgs",
    "ImportSbomArgs",
    "LibraryRefArgs",
    "ListSecurityAlertsArgs",
    "ListSecurityFindingsArgs",
    "MendDownload",
    "MendListResult",
    "MendReadResult",
    "MendReportCursor",
    "MendSCAConfig",
    "MendSnapshotCursor",
    "MendTimeCursor",
    "ParsedMendReport",
    "ProjectRefArgs",
    "RemediationArgs",
    "ReportIdentity",
    "ReportRefArgs",
    "SetAlertStatusArgs",
    "SetFindingStatusArgs",
    "VulnerabilityRefArgs",
]

_ID_PATTERN = r"^[A-Za-z0-9_.:-]{1,256}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PLAN_HASH_PATTERN = r"^[0-9a-f]{64}$"


class MendModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MendSCAConfig(ConnectorConfig):
    """One explicitly versioned Mend organization connection.

    API 2.0 and 3.0 tokens are intentionally never shared by this configuration. A
    deployment covering the same organization through both APIs needs two connections.
    """

    base_url: str = "https://api-saas.mend.io"
    api_version: Literal["3.0", "2.0"]
    email: str = Field(min_length=3, max_length=320)
    user_key: SecretRef
    org_uuid: str | None = Field(default=None, pattern=_ID_PATTERN)
    org_token: SecretRef | None = None
    selected_projects: tuple[str, ...] = Field(default_factory=tuple, max_length=100_000)
    page_size: int = Field(default=50, ge=1, le=10_000)
    max_pages: int = Field(default=10_000, ge=1, le=100_000)
    stale_after_days: int = Field(default=30, ge=1, le=3650)
    write_enabled: bool = False
    max_report_bytes: int = Field(default=32 * 1024 * 1024, ge=1024, le=256 * 1024 * 1024)
    max_report_items: int = Field(default=200_000, ge=1, le=1_000_000)
    max_report_depth: int = Field(default=64, ge=4, le=128)
    max_report_string_chars: int = Field(default=1_048_576, ge=128, le=16 * 1024 * 1024)
    max_sbom_bytes: int = Field(default=16 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024)

    @field_validator("selected_projects")
    @classmethod
    def _selected_project_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("selected_projects must not contain duplicates")
        for item in value:
            if not item or len(item) > 256 or not all(c.isalnum() or c in "_.:-" for c in item):
                raise ValueError("selected_projects contains an invalid project identifier")
        return value

    @model_validator(mode="after")
    def _versioned_organization_and_url(self) -> MendSCAConfig:
        if self.org_uuid is None and self.org_token is None:
            raise ValueError("org_uuid or org_token is required")
        if self.api_version == "3.0" and self.org_uuid is None:
            raise ValueError("api_version 3.0 requires org_uuid")
        try:
            normalized = normalize_base_url(
                self.base_url, allow_plain_http_loopback=self.allow_plain_http_loopback
            ).rstrip("/")
        except ConfigError as exc:
            raise ValueError(str(exc)) from exc
        path = urlsplit(normalized).path
        if "/api/v1." in path:
            raise ValueError("legacy Mend HTTP API 1.3 and 1.4 are not supported")
        expected = f"/api/v{self.api_version}"
        other = "/api/v2.0" if self.api_version == "3.0" else "/api/v3.0"
        if other in path:
            raise ValueError(f"base_url API path does not match api_version {self.api_version}")
        if expected not in path:
            normalized += expected
        self.base_url = normalized
        return self


class MendSnapshotCursor(SnapshotCursor):
    """Resumable full snapshot with explicit coverage and vendor page state."""

    high_water_start: datetime | None = None
    next_cursor: str | None = None
    page: int = Field(default=0, ge=0)
    pages_fetched: int = Field(default=0, ge=0)
    coverage: Literal["complete", "partial", "not_evaluated"] = "partial"
    incomplete_reason: str | None = None


class MendTimeCursor(TimeIdCursor):
    """Overlapping time/UUID cursor with an in-flight vendor page position."""

    window_end: datetime | None = None
    next_cursor: str | None = None
    page: int = Field(default=0, ge=0)
    pages_fetched: int = Field(default=0, ge=0)
    coverage: Literal["complete", "partial", "not_evaluated"] = "partial"
    incomplete_reason: str | None = None


class MendReportCursor(SnapshotCursor):
    """Report SHA-256 plus project snapshot identity."""

    report_sha256: str = Field(pattern=_SHA256_PATTERN)
    project_snapshot: str = Field(min_length=1, max_length=512)
    parser_version: int = Field(default=1, ge=1)
    coverage: Literal["complete", "partial", "not_evaluated"] = "partial"
    incomplete_reason: str | None = None


class ListSecurityAlertsArgs(MendModel):
    project_token: str = Field(pattern=_ID_PATTERN)
    modified_after: datetime | None = None
    modified_before: datetime | None = None
    page_size: int | None = Field(default=None, ge=1, le=10_000)
    max_pages: int | None = Field(default=None, ge=1, le=100_000)


class ListSecurityFindingsArgs(MendModel):
    project_uuid: str = Field(pattern=_ID_PATTERN)
    cursor: str | None = Field(default=None, max_length=4096)
    limit: int | None = Field(default=None, ge=1, le=10_000)
    max_pages: int | None = Field(default=None, ge=1, le=100_000)
    candidate_since: datetime | None = None
    candidate_only: bool = False


class ProjectRefArgs(MendModel):
    project_id: str = Field(pattern=_ID_PATTERN)


class FindingRefArgs(MendModel):
    project_id: str = Field(pattern=_ID_PATTERN)
    finding_uuid: str = Field(pattern=_ID_PATTERN)


class LibraryRefArgs(MendModel):
    project_id: str = Field(pattern=_ID_PATTERN)
    library_uuid: str = Field(pattern=_ID_PATTERN)


class VulnerabilityRefArgs(MendModel):
    vulnerability_id: str = Field(min_length=1, max_length=256)
    project_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    finding_uuid: str | None = Field(default=None, pattern=_ID_PATTERN)


class RemediationArgs(VulnerabilityRefArgs):
    pass


class GetPolicyArgs(MendModel):
    scope: Literal["orgs", "products", "projects"]
    scope_id: str = Field(pattern=_ID_PATTERN)
    policy_uuid: str = Field(pattern=_ID_PATTERN)


class ReportRefArgs(MendModel):
    report_uuid: str = Field(pattern=_ID_PATTERN)

    @field_validator("report_uuid")
    @classmethod
    def _not_dot_segment(cls, value: str) -> str:
        if value in {".", ".."}:
            raise ValueError("report_uuid must not be a relative path segment")
        return value


class DownloadReportArgs(ReportRefArgs):
    pass


class GetPermissionsArgs(MendModel):
    scope: Literal["org", "product", "project", "byRole"]
    scope_id: str | None = Field(default=None, pattern=_ID_PATTERN)


class MendListResult(MendModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    complete: bool
    pages: int = Field(ge=0)
    next_cursor: str | None = None
    total: int | None = Field(default=None, ge=0)
    authoritative: bool = True
    coverage: Literal["complete", "partial", "not_evaluated"] = "complete"


class MendReadResult(MendModel):
    data: Any
    api_version: Literal["3.0", "2.0"]
    additional_data: dict[str, Any] = Field(default_factory=dict)
    coverage: Literal["complete", "partial", "not_evaluated"] = "complete"
    authoritative: bool = True


class MendDownload(MendModel):
    """Bounded report download. ``not_ready`` (vendor HTTP 202) carries no content."""

    report_uuid: str
    status: Literal["ready", "not_ready"]
    size_bytes: int | None = Field(default=None, ge=0)
    sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    media_type: str | None = None
    content_base64: str | None = None

    @model_validator(mode="after")
    def _content_matches_status(self) -> MendDownload:
        if self.status == "ready":
            if self.content_base64 is None or self.size_bytes is None or self.sha256 is None:
                raise ValueError("ready download requires content_base64, size_bytes, and sha256")
        elif self.content_base64 is not None or self.size_bytes is not None or self.sha256 is not None:
            raise ValueError("not_ready download must not carry content")
        return self


class ReportIdentity(MendModel):
    parser_version: int = Field(default=1, ge=1)
    report_schema: Literal[
        "unified_agent_libraries",
        "manual_vulnerabilities",
        "platform_components",
        "platform_3_response",
    ]
    report_sha256: str = Field(pattern=_SHA256_PATTERN)
    project_snapshot: str = Field(min_length=1, max_length=512)
    snapshot_id: str = Field(min_length=1, max_length=256)
    project_uuid: str | None = None
    project_name: str | None = None
    application_uuid: str | None = None
    application_name: str | None = None
    last_scan: datetime | None = None
    complete: bool
    incomplete_reasons: list[str] = Field(default_factory=list)


class ParsedMendReport(MendModel):
    identity: ReportIdentity
    records: list[dict[str, Any]] = Field(default_factory=list)


class _ApprovedAction(MendModel):
    approved_plan_hash: str = Field(pattern=_PLAN_HASH_PATTERN)


class SetAlertStatusArgs(_ApprovedAction):
    project_token: str = Field(pattern=_ID_PATTERN)
    alert_uuid: str = Field(pattern=_ID_PATTERN)
    desired_status: Literal["ACTIVE", "IGNORED"]
    expected_status: str | None = Field(default=None, min_length=1, max_length=64)
    comment: str | None = Field(default=None, max_length=500)
    is_violating: bool | None = None


class SetFindingStatusArgs(_ApprovedAction):
    project_uuid: str = Field(pattern=_ID_PATTERN)
    root_library_uuid: str = Field(pattern=_ID_PATTERN)
    desired_status: Literal["UNREVIEWED", "IN_REVIEW", "SUPPRESSED"]
    expected_status: str | None = Field(default=None, min_length=1, max_length=64)
    comment: str | None = Field(default=None, max_length=500)
    is_violating: bool | None = None


class ImportSbomArgs(_ApprovedAction):
    project_uuid: str = Field(pattern=_ID_PATTERN)
    filename: str = Field(min_length=1, max_length=255)
    media_type: Literal[
        "application/json",
        "application/xml",
        "text/xml",
        "application/octet-stream",
    ] = "application/json"
    sbom_base64: str = Field(min_length=1)
    sbom_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("filename")
    @classmethod
    def _safe_filename(cls, value: str) -> str:
        if value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
            raise ValueError("filename must be a plain file name")
        return value
