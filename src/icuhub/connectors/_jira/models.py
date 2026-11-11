"""Typed inputs, outputs, and configuration shared by Jira editions."""

from __future__ import annotations

import base64
import binascii
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from icuhub.kit.types import ConnectorConfig, SecretRef


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmptyInput(StrictModel):
    pass


class SearchInput(StrictModel):
    jql: str = Field(min_length=1)
    max_results: int = Field(default=100, ge=1, le=1000)
    fields: list[str] = Field(default_factory=lambda: ["id", "key", "summary", "status", "updated"])
    next_page_token: str | None = None
    start_at: int = Field(default=0, ge=0)
    reconcile_issue_ids: list[int] = Field(default_factory=list, max_length=100)


class IssueInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    include_changelog: bool = True
    include_rendered_fields: bool = True


class IssueCommentsInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    start_at: int = Field(default=0, ge=0)
    max_results: int = Field(default=100, ge=1, le=1000)


class CreateMetadataInput(StrictModel):
    project_id_or_key: str = Field(min_length=1)
    issue_type_id: str | None = None
    start_at: int = Field(default=0, ge=0)
    max_results: int = Field(default=100, ge=1, le=1000)


class EditMetadataInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)


class PropertyInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    property_key: str = Field(default="icuhub.action_key", min_length=1)


class DownloadAttachmentInput(StrictModel):
    attachment_id: str = Field(min_length=1)
    max_bytes: int = Field(default=16 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)


class AttachmentContent(StrictModel):
    attachment_id: str
    filename: str
    media_type: str | None
    size: int
    sha256: str
    content_base64: str


class CreateIssueInput(StrictModel):
    route_key: str = Field(min_length=1, max_length=512)
    project_key: str = Field(min_length=1)
    issue_type: str = Field(min_length=1)
    summary: str = Field(min_length=1, max_length=255)
    description: str | dict[str, Any] | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    labels: list[str] = Field(default_factory=list)
    fingerprint_links: list[str] = Field(default_factory=list)

    @field_validator("labels", "fingerprint_links")
    @classmethod
    def _no_empty_labels(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 255 for value in values):
            raise ValueError("labels and fingerprint links must contain 1 to 255 characters")
        return values


class UpdateIssueInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    expected_id: str = Field(min_length=1)
    expected_updated: str = Field(min_length=1)
    expected_status: str = Field(min_length=1)
    fields: dict[str, Any] = Field(min_length=1)


class AddCommentInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    action_key: str = Field(min_length=1, max_length=255)
    body: str | dict[str, Any]
    visibility: dict[str, Any] | None = None


class UpdateCommentInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    comment_id: str = Field(min_length=1)
    expected_updated: str = Field(min_length=1)
    body: str | dict[str, Any]


class TransitionIssueInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    to_status: str = Field(min_length=1)
    fields: dict[str, Any] = Field(default_factory=dict)


class LinkIssueInput(StrictModel):
    inward_issue: str = Field(min_length=1)
    outward_issue: str = Field(min_length=1)
    link_type: str = Field(min_length=1)
    comment: str | dict[str, Any] | None = None


class RemoteLinkInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    global_id: str = Field(min_length=1, max_length=2048)
    url: str = Field(min_length=1, max_length=2048)
    title: str = Field(min_length=1, max_length=1024)
    icon: dict[str, Any] | None = None


class AttachmentInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    filename: str = Field(min_length=1, max_length=255)
    media_type: str = Field(default="application/octet-stream", min_length=1)
    content_base64: str = Field(min_length=1)

    @field_validator("filename")
    @classmethod
    def _safe_filename(cls, value: str) -> str:
        if value in {".", ".."} or any(char in value for char in ("/", "\\", "\x00", "\r", "\n")):
            raise ValueError("filename must be one safe path segment")
        return value

    @field_validator("content_base64")
    @classmethod
    def _valid_content(cls, value: str) -> str:
        try:
            base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("content_base64 must be valid base64") from exc
        return value


class DeleteIssueInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    expected_id: str = Field(min_length=1)
    delete_subtasks: bool = False


class DeleteCommentInput(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    comment_id: str = Field(min_length=1)
    expected_updated: str = Field(min_length=1)


class DeleteAttachmentInput(StrictModel):
    attachment_id: str = Field(min_length=1)
    expected_created: str = Field(min_length=1)


class CreateWebhookInput(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    url: str = Field(min_length=1, max_length=2048)
    events: list[str] = Field(min_length=1)
    jql_filter: str = ""

    @field_validator("events")
    @classmethod
    def _supported_events(cls, values: list[str]) -> list[str]:
        supported = {
            "jira:issue_created",
            "jira:issue_updated",
            "jira:issue_deleted",
            "comment_created",
            "comment_updated",
            "comment_deleted",
        }
        unknown = sorted(set(values) - supported)
        if unknown:
            raise ValueError(f"unsupported Jira webhook events: {','.join(unknown)}")
        return sorted(set(values))


class DeleteWebhookInput(StrictModel):
    webhook_id: str = Field(min_length=1)
    expected_url: str = Field(min_length=1)


class RefreshWebhookInput(StrictModel):
    webhook_ids: list[str] = Field(min_length=1, max_length=100)


class AuditFileSource(StrictModel):
    """One node-local JSONL audit file exposed by the TLS file collector."""

    node: str = Field(min_length=1, max_length=255)
    path: str = Field(min_length=1, max_length=1024)
    url: str = Field(min_length=1, max_length=2048)


class JiraConfig(ConnectorConfig):
    """Connection controls shared by Cloud and Data Center."""

    jql: str = "ORDER BY updated ASC, id ASC"
    page_size: int = Field(default=100, ge=1, le=1000)
    max_pages: int = Field(default=10_000, ge=1, le=100_000)
    max_tie_ids: int = Field(default=10_000, ge=100, le=1_000_000)
    attachment_max_bytes: int = Field(default=16 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)
    audit_max_bytes: int = Field(default=64 * 1024 * 1024, ge=1, le=256 * 1024 * 1024)
    destructive_enabled: bool = False


class JiraCloudConfig(JiraConfig):
    auth_method: Literal["basic", "oauth2_3lo", "bearer"] = "basic"
    account_email: str | None = None
    api_token: SecretRef | None = None
    access_token: SecretRef | None = None
    refresh_token: SecretRef | None = None
    client_id: str | None = None
    client_secret: SecretRef | None = None
    cloud_id: str | None = None

    @model_validator(mode="after")
    def _validate_auth(self) -> JiraCloudConfig:
        if self.auth_method == "basic" and (not self.account_email or self.api_token is None):
            raise ValueError("basic auth requires account_email and api_token")
        if self.auth_method == "bearer" and self.access_token is None:
            raise ValueError("bearer auth requires access_token")
        if self.auth_method == "oauth2_3lo":
            if not self.cloud_id or not self.client_id or self.client_secret is None or self.refresh_token is None:
                raise ValueError("oauth2_3lo requires cloud_id, client_id, client_secret, and refresh_token")
            expected = f"/ex/jira/{self.cloud_id}"
            if "api.atlassian.com" not in self.base_url or expected not in self.base_url:
                raise ValueError("oauth2_3lo base_url must use the selected api.atlassian.com cloudId gateway")
        return self


class JiraDataCenterConfig(JiraConfig):
    personal_access_token: SecretRef
    webhook_registration_family: Literal["auto", "pre_10", "jira_10"] = "auto"
    audit_files: tuple[AuditFileSource, ...] = ()
    audit_collector_token: SecretRef | None = None
    audit_collector_client_cert: SecretRef | None = None
    audit_collector_client_key: SecretRef | None = None
    audit_collector_ca_bundle: SecretRef | None = None

    @model_validator(mode="after")
    def _validate_audit_collector(self) -> JiraDataCenterConfig:
        if (self.audit_collector_client_cert is None) != (self.audit_collector_client_key is None):
            raise ValueError("audit_collector_client_cert and audit_collector_client_key must be configured together")
        if not self.audit_files:
            return self
        if self.audit_collector_token is None:
            raise ValueError("audit_files require audit_collector_token; the Jira token is never sent to the collector")
        parts = [urlsplit(source.url) for source in self.audit_files]
        if any(part.scheme != "https" or not part.netloc for part in parts):
            raise ValueError("audit_files URLs must be absolute https URLs served by the TLS file collector")
        if len({(part.scheme, part.netloc) for part in parts}) != 1:
            raise ValueError("audit_files must all be served by one collector origin")
        return self

