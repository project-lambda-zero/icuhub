"""Strict configuration, read, and action contracts for Prisma Cloud."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = [
    "AccountInput",
    "AlertExportInput",
    "AlertIdInput",
    "AlertListInput",
    "AuditListInput",
    "CollectionInput",
    "CompliancePostureInput",
    "ComputeIdInput",
    "ComputeQueryInput",
    "DeleteCollectionInput",
    "DismissAlertInput",
    "DownloadExportInput",
    "EmptyInput",
    "ExportDownloadResult",
    "ExportJobInput",
    "IncidentInput",
    "InventoryInput",
    "PolicyListInput",
    "PrismaCloudConfig",
    "ReadResult",
    "RemediateAlertInput",
    "ReopenAlertInput",
    "ResourceInput",
    "ReversalArgs",
    "RqlInput",
    "RqlPageInput",
    "RuntimeTimesliceInput",
    "SnoozeAlertInput",
    "StartRegistryScanInput",
    "StrictModel",
    "SuppressionArgs",
    "SuppressionPolicyConfig",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmptyInput(StrictModel):
    pass


class AlertListInput(StrictModel):
    detailed: bool = True
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)
    page_token: str | None = None
    start_time_ms: int | None = Field(default=None, ge=0)
    end_time_ms: int | None = Field(default=None, ge=0)
    statuses: list[str] = Field(default_factory=list)
    policy_types: list[str] = Field(default_factory=list)
    account_ids: list[str] = Field(default_factory=list)


class AlertIdInput(StrictModel):
    alert_id: str = Field(min_length=1, max_length=512)


class AlertExportInput(StrictModel):
    format: Literal["json", "csv"] = "json"
    start_time_ms: int | None = Field(default=None, ge=0)
    end_time_ms: int | None = Field(default=None, ge=0)
    statuses: list[str] = Field(default_factory=list)
    policy_types: list[str] = Field(default_factory=list)
    account_ids: list[str] = Field(default_factory=list)


class ExportJobInput(StrictModel):
    job_id: str = Field(min_length=1, max_length=512)
    timeout_s: float = Field(default=900, gt=0, le=86400)
    poll_interval_s: float = Field(default=1, ge=0, le=60)


class DownloadExportInput(StrictModel):
    job_id: str = Field(min_length=1, max_length=512)
    max_bytes: int = Field(default=64 * 1024 * 1024, ge=1, le=1024 * 1024 * 1024)


class CompliancePostureInput(StrictModel):
    standard: str | None = None
    requirement: str | None = None
    section: str | None = None
    account_ids: list[str] = Field(default_factory=list)
    end_time_ms: int | None = Field(default=None, ge=0)


class PolicyListInput(StrictModel):
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)
    policy_types: list[str] = Field(default_factory=list)


class RqlInput(StrictModel):
    query: str = Field(min_length=1, max_length=32768)
    limit: int = Field(default=50, ge=1, le=1000)
    page_token: str | None = None
    time_range: dict[str, Any] | None = None


class RqlPageInput(StrictModel):
    query: str = Field(min_length=1, max_length=32768)
    page_token: str = Field(min_length=1)
    limit: int = Field(default=50, ge=1, le=1000)
    time_range: dict[str, Any] | None = None
    expected_metadata: dict[str, Any] = Field(default_factory=dict)


class InventoryInput(StrictModel):
    query: str | None = None
    account_ids: list[str] = Field(default_factory=list)
    end_time_ms: int | None = Field(default=None, ge=0)


class ResourceInput(StrictModel):
    resource_id: str | None = None
    rrn: str | None = None
    query: str | None = None
    limit: int = Field(default=50, ge=1, le=1000)
    page_token: str | None = None
    expected_metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _selector_present(self) -> ResourceInput:
        if not (self.resource_id or self.rrn or self.query):
            raise ValueError("resource_id, rrn, or query is required")
        return self


class AccountInput(StrictModel):
    account_id: str = Field(min_length=1, max_length=512)
    cloud_type: str | None = None


class AuditListInput(StrictModel):
    start_time_ms: int | None = Field(default=None, ge=0)
    end_time_ms: int | None = Field(default=None, ge=0)
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)
    page_token: str | None = None


class ComputeQueryInput(StrictModel):
    limit: int = Field(default=50, ge=1, le=50)
    offset: int = Field(default=0, ge=0)
    collections: list[str] = Field(default_factory=list)
    acknowledged: bool | None = None
    image: str | None = None
    hostname: str | None = None
    container_id: str | None = None
    repository: str | None = None
    digest: str | None = None
    audit_type: str | None = None
    start_time_ms: int | None = Field(default=None, ge=0)
    end_time_ms: int | None = Field(default=None, ge=0)


class ComputeIdInput(StrictModel):
    id: str = Field(min_length=1, max_length=2048)
    acknowledged: bool | None = None


class RuntimeTimesliceInput(StrictModel):
    start_time_ms: int = Field(ge=0)
    end_time_ms: int = Field(ge=0)
    collections: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _valid_window(self) -> RuntimeTimesliceInput:
        if self.end_time_ms < self.start_time_ms:
            raise ValueError("end_time_ms must not precede start_time_ms")
        return self


class ReadResult(StrictModel):
    data: Any = None
    items: list[dict[str, Any]] = Field(default_factory=list)
    next_page_token: str | None = None
    total: int | None = None
    pages: int = 0
    complete: bool = True


class ExportDownloadResult(StrictModel):
    job_id: str
    sha256: str
    size_bytes: int
    media_type: str
    content_base64: str
    records: list[dict[str, Any]] = Field(default_factory=list)
    complete: bool = True


class DismissAlertInput(StrictModel):
    alert_id: str = Field(min_length=1, max_length=512)
    note: str = Field(min_length=1, max_length=4096)


class SnoozeAlertInput(StrictModel):
    alert_id: str = Field(min_length=1, max_length=512)
    dismiss_until: datetime
    note: str = Field(min_length=1, max_length=4096)

    @field_validator("dismiss_until")
    @classmethod
    def _future_aware_window(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("dismiss_until must be timezone-aware")
        if value.astimezone(UTC) <= datetime.now(UTC):
            raise ValueError("dismiss_until must be in the future")
        return value


class ReopenAlertInput(StrictModel):
    alert_id: str = Field(min_length=1, max_length=512)
    note: str | None = Field(default=None, max_length=4096)


class RemediateAlertInput(StrictModel):
    alert_id: str = Field(min_length=1, max_length=512)
    approved: bool = False

    @model_validator(mode="after")
    def _explicit_approval(self) -> RemediateAlertInput:
        if not self.approved:
            raise ValueError("remediate_alert requires approved=true")
        return self


class StartRegistryScanInput(StrictModel):
    registry: str = Field(min_length=1, max_length=2048)
    repository: str | None = Field(default=None, max_length=2048)
    digest: str | None = Field(default=None, max_length=256)
    on_demand: bool = False


class IncidentInput(StrictModel):
    incident_id: str = Field(min_length=1, max_length=512)


class CollectionInput(StrictModel):
    name: str = Field(min_length=1, max_length=512)
    description: str = Field(default="", max_length=4096)
    color: str = Field(default="#000000", max_length=32)
    resources: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _safe_name(cls, value: str) -> str:
        if any(char in value for char in ("/", "\\", "\x00", "\r", "\n")):
            raise ValueError("collection name must be one safe path segment")
        return value


class DeleteCollectionInput(StrictModel):
    name: str = Field(min_length=1, max_length=512)

    @field_validator("name")
    @classmethod
    def _safe_name(cls, value: str) -> str:
        if any(char in value for char in ("/", "\\", "\x00", "\r", "\n")):
            raise ValueError("collection name must be one safe path segment")
        return value


class SuppressionArgs(StrictModel):
    """Templated ``snooze_alert`` arguments; ``{key}`` placeholders are rendered per case (FR-GRC-04)."""

    alert_id: str = Field(min_length=1, max_length=512)
    dismiss_until: str = Field(min_length=1, max_length=256)
    note: str = Field(min_length=1, max_length=4096)


class ReversalArgs(StrictModel):
    """Templated ``reopen_alert`` arguments used when an approved exception stops suppressing."""

    alert_id: str = Field(min_length=1, max_length=512)
    note: str | None = Field(default=None, max_length=4096)


class SuppressionPolicyConfig(StrictModel):
    """Vendor action pair F3 submits to suppress and restore one Prisma alert."""

    action: Literal["snooze_alert"]
    args: SuppressionArgs
    reversal_action: Literal["reopen_alert"]
    reversal_args: ReversalArgs


class PrismaCloudConfig(ConnectorConfig):
    """Independent CSPM and Compute profiles on one connector kind."""

    editions: list[Literal["cspm", "compute"]] = Field(min_length=1, max_length=2)
    suppression: SuppressionPolicyConfig | None = None
    cspm_base_url: str | None = None
    compute_base_url: str | None = None
    cspm_access_key_id: str | None = None
    cspm_access_key_secret: SecretRef | None = None
    compute_auth_mode: Literal["session", "basic"] = "session"
    compute_username: str | None = None
    compute_password: SecretRef | None = None
    compute_api_version: str = Field(default="1", pattern=r"^[0-9]+$")
    compute_project: str | None = None
    compute_collections: list[str] = Field(default_factory=list)
    extra_hosts: tuple[str, ...] = ()
    page_size: int = Field(default=50, ge=1, le=1000)
    max_pages: int = Field(default=10000, ge=1, le=100000)
    alert_overlap_s: int = Field(default=300, ge=0, le=86400)
    export_max_bytes: int = Field(default=64 * 1024 * 1024, ge=1, le=1024 * 1024 * 1024)
    destructive_enabled: bool = False

    @model_validator(mode="after")
    def _validate_profiles(self) -> PrismaCloudConfig:
        if len(set(self.editions)) != len(self.editions):
            raise ValueError("editions must not contain duplicates")
        if "cspm" in self.editions and not (self.cspm_access_key_id and self.cspm_access_key_secret):
            raise ValueError("cspm requires cspm_access_key_id and cspm_access_key_secret")
        if "compute" in self.editions and not (self.compute_username and self.compute_password):
            raise ValueError("compute requires compute_username and compute_password")
        if len(self.editions) == 2 and not (self.cspm_base_url and self.compute_base_url):
            raise ValueError("dual-profile connections require cspm_base_url and compute_base_url")
        return self
