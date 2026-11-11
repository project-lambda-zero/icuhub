"""Typed configuration, operation inputs, and vendor records for Fortify SSC."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = [
    "AddIssueCommentArgs",
    "ArtifactArgs",
    "ArtifactOutput",
    "ArtifactStatus",
    "AssignIssueArgs",
    "AuditIssueArgs",
    "CreateWebhookArgs",
    "FortifySscConfig",
    "GetIssueArgs",
    "IssueAuditArgs",
    "IssueAuditOutput",
    "IssueAuditRecord",
    "IssueCommentArgs",
    "IssueCommentOutput",
    "IssueCommentRecord",
    "IssueDetailArgs",
    "IssueDetailOutput",
    "IssueDetailRecord",
    "IssueListArgs",
    "IssueListOutput",
    "IssueRecord",
    "LicenseCapability",
    "ProbeArgs",
    "ProjectVersionListArgs",
    "ProjectVersionListOutput",
    "ProjectVersionInfo",
    "ProjectVersionRecord",
    "PurgeArtifactArgs",
    "PurgeProjectVersionArgs",
    "SetIssueSuppressionArgs",
    "StrictModel",
    "TargetProbeOutput",
    "UploadFprArgs",
    "VendorModel",
    "WebhookDefinitionRecord",
    "WebhookDeliveryRecord",
    "WebhookHistoryArgs",
    "WebhookHistoryOutput",
    "WebhookListArgs",
    "WebhookListOutput",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VendorModel(BaseModel):
    """Typed projection of a vendor object; unknown SSC fields remain in raw stream evidence."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class FortifySscConfig(ConnectorConfig):
    """SSC connection settings. ``base_url`` is the operator root, normally ``https://host/ssc``."""

    api_token: SecretRef
    webhook_secret: SecretRef | None = None
    fpr_location_semantics: Literal["source_location_v2", "snippet_start_v1"] = "source_location_v2"
    write_enabled: bool = False
    destructive_enabled: bool = False


class ProbeArgs(StrictModel):
    pass


class PageArgs(StrictModel):
    limit: int = Field(default=200, ge=1, le=1000)
    max_pages: int = Field(default=100, ge=1, le=10_000)


class ProjectVersionListArgs(PageArgs):
    include_inactive: bool = True


class IssueListArgs(PageArgs):
    project_version_id: int = Field(ge=1)


class GetIssueArgs(StrictModel):
    project_version_id: int = Field(ge=1)
    issue_id: int = Field(ge=1)


class IssueDetailArgs(GetIssueArgs):
    pass


class IssueAuditArgs(GetIssueArgs):
    # SSC auditHistory has no paging parameters. The read rejects an over-bound response.
    limit: int = Field(default=1000, ge=1, le=10_000)


class IssueCommentArgs(GetIssueArgs):
    limit: int = Field(default=200, ge=1, le=1000)
    max_pages: int = Field(default=100, ge=1, le=10_000)


class ArtifactArgs(StrictModel):
    artifact_id: int = Field(ge=1)


class WebhookListArgs(PageArgs):
    pass


class WebhookHistoryArgs(PageArgs):
    webhook_id: int = Field(ge=1)


class LicenseCapability(VendorModel):
    key: str
    value: str
    expiration_date: datetime | None = None


class TargetProbeOutput(VendorModel):
    target_version: str = Field(alias="webappVersion", min_length=1)
    effective_context_root: str = Field(alias="applicationContextPath", min_length=1)
    capabilities: list[LicenseCapability] = Field(alias="licenseCapabilities")
    permissions: list[str]


class IssueRecord(VendorModel):
    issue_id: int = Field(alias="id", ge=1)
    issue_instance_id: str = Field(alias="issueInstanceId", min_length=1)
    project_version_id: int = Field(alias="projectVersionId", ge=1)
    revision: int = Field(ge=0)
    issue_name: str | None = Field(default=None, validation_alias=AliasChoices("issueName", "category"))
    primary_rule_guid: str | None = Field(default=None, alias="primaryRuleGuid")
    full_file_name: str | None = Field(
        default=None, validation_alias=AliasChoices("fullFileName", "fileName")
    )
    line_number: int | None = Field(default=None, alias="lineNumber")
    found_date: datetime | None = Field(default=None, alias="foundDate")
    removed_date: datetime | None = Field(default=None, alias="removedDate")
    hidden: bool = False
    removed: bool = False
    suppressed: bool = False


class IssueDetailRecord(IssueRecord):
    detail: str | None = Field(default=None, max_length=1_048_576)
    brief: str | None = Field(default=None, max_length=1_048_576)
    recommendation: str | None = Field(default=None, max_length=1_048_576)
    references: str | None = Field(default=None, max_length=1_048_576)
    tips: str | None = Field(default=None, max_length=1_048_576)
    trace_nodes: list[list[dict[str, Any]]] = Field(default_factory=list, alias="traceNodes", max_length=1000)


class IssueAuditRecord(VendorModel):
    sequence_number: int = Field(alias="sequenceNumber", ge=0)
    issue_id: int = Field(alias="issueId", ge=1)
    audit_date_time: datetime = Field(alias="auditDateTime")
    attribute_name: str = Field(alias="attributeName")
    old_value: str | None = Field(default=None, alias="oldValue", max_length=1_048_576)
    new_value: str | None = Field(default=None, alias="newValue", max_length=1_048_576)
    user_name: str = Field(alias="userName")
    value_type: str = Field(alias="valueType")
    conflict: bool = False


class IssueCommentRecord(VendorModel):
    sequence_number: int = Field(alias="seqNumber", ge=0)
    issue_id: int = Field(alias="issueId", ge=1)
    project_version_id: int | None = Field(default=None, alias="projectVersionId", ge=1)
    comment: str = Field(max_length=1_048_576)
    audit_time: datetime = Field(alias="auditTime")
    user_name: str = Field(alias="userName")


class ArtifactStatus(VendorModel):
    artifact_id: int = Field(alias="id", ge=1)
    project_version_id: int = Field(alias="projectVersionId", ge=1)
    status: str
    indexed: bool = False
    version_number: int = Field(alias="versionNumber", ge=0)
    purged: bool = False
    allow_purge: bool | None = Field(default=None, alias="allowPurge")


class WebhookDefinitionRecord(VendorModel):
    webhook_id: int = Field(alias="id", ge=1)
    object_version: int = Field(alias="objectVersion", ge=0)
    content_type: Literal["JSON"] = Field(alias="contentType")
    url: str = Field(min_length=1)
    description: str | None = None
    active: bool | None = None
    allow_insecure_tls: bool = Field(default=False, alias="allowInsecureTLS")
    last_status: Literal["NONE", "SUCCESS", "FAILED"] | None = Field(default=None, alias="lastStatus")
    monitor_apps: Literal["ALL", "CUSTOM"] | None = Field(default=None, alias="monitorApps")
    monitor_events: Literal["ALL", "CUSTOM"] | None = Field(default=None, alias="monitorEvents")
    monitored_app_version_ids: list[int] = Field(default_factory=list, alias="monitoredAppVersionIds")
    monitored_app_version_events: list[str] = Field(default_factory=list, alias="monitoredAppVersionEvents")
    monitored_global_events: list[str] = Field(default_factory=list, alias="monitoredGlobalEvents")


class WebhookDeliveryRecord(VendorModel):
    delivery_id: int = Field(alias="id", ge=1)
    webhook_id: int = Field(alias="webHookId", ge=1)
    created_at: datetime = Field(alias="createdAt")
    status: Literal["PENDING", "SENT", "SUCCESS", "FAILED"]
    response_code: int | None = Field(default=None, alias="responseCode")
    failure_reason: str | None = Field(default=None, alias="failureReason", max_length=16_384)


class ProjectVersionRecord(StrictModel):
    project_version_id: int
    project_name: str | None = None
    version_name: str
    folder_guid: str | None = None


class ProjectVersionInfo(StrictModel):
    record: ProjectVersionRecord


class ProjectVersionListOutput(StrictModel):
    records: list[ProjectVersionRecord]


class IssueListOutput(StrictModel):
    issues: list[IssueRecord]


class IssueDetailOutput(StrictModel):
    issue: IssueDetailRecord


class IssueAuditOutput(StrictModel):
    audit: list[IssueAuditRecord]


class IssueCommentOutput(StrictModel):
    comments: list[IssueCommentRecord]


class ArtifactOutput(StrictModel):
    artifact: ArtifactStatus


class WebhookListOutput(StrictModel):
    webhooks: list[WebhookDefinitionRecord]


class WebhookHistoryOutput(StrictModel):
    deliveries: list[WebhookDeliveryRecord]


class AuditIssueArgs(StrictModel):
    project_version_id: int = Field(ge=1)
    issue_id: int = Field(ge=1)
    revision: int = Field(ge=0)
    custom_tag_guid: str = Field(min_length=1, max_length=64)
    new_custom_tag_index: int = Field(ge=0)
    comment: str | None = Field(default=None, max_length=4000)


class SetIssueSuppressionArgs(StrictModel):
    project_version_id: int = Field(ge=1)
    issue_id: int = Field(ge=1)
    revision: int = Field(ge=0)
    suppressed: bool


class AssignIssueArgs(StrictModel):
    project_version_id: int = Field(ge=1)
    issue_id: int = Field(ge=1)
    revision: int = Field(ge=0)
    assignee: str = Field(min_length=1, max_length=255)


class AddIssueCommentArgs(StrictModel):
    project_version_id: int = Field(ge=1)
    issue_id: int = Field(ge=1)
    revision: int = Field(ge=0)
    comment: str = Field(min_length=1, max_length=4000)


class UploadFprArgs(StrictModel):
    project_version_id: int = Field(ge=1)
    fpr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fpr_base64: str = Field(min_length=1)


class CreateWebhookArgs(StrictModel):
    url: str = Field(min_length=1)
    object_version: int = Field(default=0, ge=0)
    content_type: Literal["JSON"] = "JSON"
    active: bool = True
    allow_insecure_tls: bool = False
    monitor_apps: Literal["ALL", "CUSTOM"] = "ALL"
    monitor_events: Literal["ALL", "CUSTOM"] = "ALL"
    monitored_app_version_ids: list[int] = Field(default_factory=list)
    monitored_app_version_events: list[str] = Field(default_factory=list)
    monitored_global_events: list[str] = Field(default_factory=list)


class PurgeArtifactArgs(StrictModel):
    artifact_id: int = Field(ge=1)
    version_number: int = Field(ge=0)
    approval_ref: str = Field(min_length=1)


class PurgeProjectVersionArgs(StrictModel):
    project_version_id: int = Field(ge=1)
    approval_ref: str = Field(min_length=1)
