"""Typed configuration, operation inputs, and action arguments for the Fortify SSC connector."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = [
    "AddIssueCommentArgs",
    "AssignIssueArgs",
    "AuditIssueArgs",
    "CreateWebhookArgs",
    "FortifySscConfig",
    "GetIssueArgs",
    "IssueListArgs",
    "PurgeArtifactArgs",
    "PurgeProjectVersionArgs",
    "SetIssueSuppressionArgs",
    "StrictModel",
    "UploadFprArgs",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FortifySscConfig(ConnectorConfig):
    """SSC connection settings. ``base_url`` is the operator root, normally ``https://host/ssc``."""

    api_token: SecretRef
    webhook_secret: SecretRef | None = None
    fpr_location_semantics: Literal["source_location_v2", "snippet_start_v1"] = "source_location_v2"
    write_enabled: bool = False
    destructive_enabled: bool = False


class IssueListArgs(StrictModel):
    project_version_id: int = Field(ge=1)
    limit: int = Field(default=200, ge=1, le=1000)


class GetIssueArgs(StrictModel):
    project_version_id: int = Field(ge=1)
    issue_id: int = Field(ge=1)


class AuditIssueArgs(StrictModel):
    project_version_id: int = Field(ge=1)
    issue_id: int = Field(ge=1)
    revision: int = Field(ge=0)
    audit_state: str = Field(min_length=1, max_length=64)
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
    auto_publish: bool = False


class CreateWebhookArgs(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    target_url: str = Field(min_length=1)
    event_types: list[str] = Field(min_length=1)
    object_version: int | None = Field(default=None, ge=0)


class PurgeArtifactArgs(StrictModel):
    artifact_id: int = Field(ge=1)
    version_number: int = Field(ge=0)
    approval_ref: str = Field(min_length=1)


class PurgeProjectVersionArgs(StrictModel):
    project_version_id: int = Field(ge=1)
    approval_ref: str = Field(min_length=1)
