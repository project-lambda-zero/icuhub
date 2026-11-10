"""Configuration and typed vendor inputs for the GitLab connector family."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from icuhub.kit._urls import normalize_base_url
from icuhub.kit.errors import ConfigError
from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = [
    "ApproveMergeRequestArgs",
    "ArtifactRef",
    "AuditObjectRef",
    "ChangeVulnerabilityStateArgs",
    "CommitRef",
    "MergeRequestRef",
    "PipelineRef",
    "VulnerabilityRef",
    "ControlJobArgs",
    "ControlPipelineArgs",
    "CreateMergeRequestArgs",
    "CreateMrNoteOrDiscussionArgs",
    "CreateVulnerabilityExportInput",
    "DiffPosition",
    "DownloadVulnerabilityExportInput",
    "EmptyArgs",
    "ExportRef",
    "GitLabConfig",
    "GroupRef",
    "JobRef",
    "ListAuditEventsInput",
    "ListMergeRequestsInput",
    "ListVulnerabilitiesInput",
    "MergeMergeRequestArgs",
    "MergeRequestRef",
    "PipelineRef",
    "ProjectRef",
    "PublishSecurityReportArtifactArgs",
    "RepositoryPathRef",
    "SelfManagedGitLabConfig",
    "VendorResult",
    "VulnerabilityRef",
    "WebhookRef",
]

_MAX_ID = 9_223_372_036_854_775_807
_MAX_PAGE = 100_000
_SHA_PATTERN = r"^[0-9a-fA-F]{7,64}$"
_PLAN_HASH_PATTERN = r"^[0-9a-f]{64}$"
_ACTION_KEY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$"

_PositiveId = Annotated[int, Field(ge=1, le=_MAX_ID)]
_PositivePage = Annotated[int, Field(ge=1, le=_MAX_PAGE)]
_BranchName = Annotated[str, Field(min_length=1, max_length=255)]
_Path = Annotated[str, Field(min_length=1, max_length=4096)]
_Sha = Annotated[str, Field(pattern=_SHA_PATTERN)]
_PlanHash = Annotated[str, Field(pattern=_PLAN_HASH_PATTERN)]
_ActionKey = Annotated[str, Field(pattern=_ACTION_KEY_PATTERN)]
_Status = Annotated[str, Field(min_length=1, max_length=64)]
_FindingUid = Annotated[str, Field(min_length=1, max_length=512)]


class StrictModel(BaseModel):
    """Strict base for GitLab operation inputs and results."""

    model_config = ConfigDict(extra="forbid")


class GitLabConfig(ConnectorConfig):
    """GitLab API, authentication, pagination, and evidence bounds."""

    base_url: str = Field(default="https://gitlab.com/api/v4", min_length=1, max_length=2048)
    auth_method: Literal["private_token", "oauth_bearer", "job_token"] = "private_token"
    access_token: SecretRef
    principal_kind: Literal["personal", "project", "group", "oauth", "ci_job"] = "personal"
    webhook_tolerance_s: int = Field(default=300, ge=0)
    page_size: int = Field(default=100, ge=1, le=100)
    max_pages: int = Field(default=1000, ge=1, le=100_000)
    overlap_s: int = Field(default=300, ge=0)
    max_tie_ids: int = Field(default=10_000, ge=1, le=1_000_000)
    write_enabled: bool = False
    destructive_enabled: bool = False
    max_job_log_bytes: int = Field(default=1024 * 1024, ge=1, le=10 * 1024 * 1024)
    max_artifact_bytes: int = Field(default=10 * 1024 * 1024, ge=1, le=10 * 1024 * 1024)
    max_export_bytes: int = Field(default=25 * 1024 * 1024, ge=1, le=100 * 1024 * 1024)
    max_sarif_runs: int = Field(default=20, ge=1, le=20)
    max_sarif_results_per_run: int = Field(default=5000, ge=1, le=5000)
    publication_poll_interval_s: float = Field(default=2.0, gt=0)
    publication_max_polls: int = Field(default=60, ge=1, le=10_000)

    @model_validator(mode="after")
    def _validate_connection(self) -> GitLabConfig:
        try:
            normalize_base_url(
                self.base_url,
                allow_plain_http_loopback=self.allow_plain_http_loopback,
            )
        except ConfigError as exc:
            raise ValueError(str(exc)) from exc

        allowed_kinds = {
            "private_token": {"personal", "project", "group"},
            "oauth_bearer": {"oauth"},
            "job_token": {"ci_job"},
        }
        if self.principal_kind not in allowed_kinds[self.auth_method]:
            raise ValueError(
                f"principal_kind {self.principal_kind!r} is incompatible with auth_method {self.auth_method!r}"
            )
        return self


class SelfManagedGitLabConfig(GitLabConfig):
    """GitLab Self-Managed or Dedicated configuration with an explicit API root."""

    @model_validator(mode="before")
    @classmethod
    def _require_base_url(cls, data: Any) -> Any:
        if not isinstance(data, dict) or not data.get("base_url"):
            raise ValueError("base_url is required for GitLab Self-Managed and Dedicated")
        return data

    @model_validator(mode="after")
    def _reject_gitlab_com(self) -> SelfManagedGitLabConfig:
        hostname = (urlsplit(self.base_url).hostname or "").rstrip(".").lower()
        if hostname == "gitlab.com":
            raise ValueError("SelfManagedGitLabConfig requires a non-GitLab.com API root")
        return self


class EmptyArgs(StrictModel):
    pass


class ProjectRef(StrictModel):
    project_id: _PositiveId


class GroupRef(StrictModel):
    group_id: _PositiveId


class ExportRef(StrictModel):
    export_id: _PositiveId


class JobRef(ProjectRef):
    job_id: _PositiveId


class RepositoryPathRef(ProjectRef):
    path: _Path
    ref: _BranchName | None = None


class CommitRef(ProjectRef):
    sha: _Sha


class MergeRequestRef(ProjectRef):
    iid: _PositiveId


class PipelineRef(ProjectRef):
    pipeline_id: _PositiveId


class VulnerabilityRef(StrictModel):
    vulnerability_id: _PositiveId


class ArtifactRef(JobRef):
    artifact_path: _Path | None = None


class AuditObjectRef(StrictModel):
    object_key: Annotated[str, Field(min_length=1, max_length=1024)]


class WebhookRef(ProjectRef):
    hook_id: _PositiveId
    test_event: Annotated[str, Field(min_length=1, max_length=512)] | None = None


class ListMergeRequestsInput(StrictModel):
    project_id: _PositiveId | None = None
    state: Literal["opened", "closed", "locked", "merged", "all"] | None = None
    updated_after: datetime | None = None
    updated_before: datetime | None = None
    page: _PositivePage = 1

    @field_validator("updated_after", "updated_before")
    @classmethod
    def _aware_timestamps(cls, value: datetime | None) -> datetime | None:
        return _require_aware(value)


class ListVulnerabilitiesInput(ProjectRef):
    pass


class CreateVulnerabilityExportInput(StrictModel):
    project_id: _PositiveId | None = None
    group_id: _PositiveId | None = None
    authorized_instance: bool = False
    approved_plan_hash: _PlanHash | None = None

    @model_validator(mode="after")
    def _exactly_one_scope(self) -> CreateVulnerabilityExportInput:
        scopes = (self.project_id is not None, self.group_id is not None, self.authorized_instance)
        if sum(scopes) != 1:
            raise ValueError("configure exactly one of project_id, group_id, or authorized_instance")
        return self


class DownloadVulnerabilityExportInput(ExportRef):
    pass


class ListAuditEventsInput(StrictModel):
    project_id: _PositiveId | None = None
    group_id: _PositiveId | None = None
    created_after: datetime | None = None
    created_before: datetime | None = None

    @field_validator("created_after", "created_before")
    @classmethod
    def _aware_timestamps(cls, value: datetime | None) -> datetime | None:
        return _require_aware(value)


class DiffPosition(StrictModel):
    """Merge request diff position; all fields are required together."""

    base_sha: _Sha
    head_sha: _Sha
    start_sha: _Sha
    path: _Path
    line: Annotated[int, Field(ge=1, le=1_000_000)]


class CreateMergeRequestArgs(ProjectRef):
    source_branch: _BranchName
    target_branch: _BranchName
    title: Annotated[str, Field(min_length=1, max_length=255)]
    description: Annotated[str, Field(max_length=60_000)] | None = None
    action_key: _ActionKey
    approved_plan_hash: _PlanHash


class CreateMrNoteOrDiscussionArgs(ProjectRef):
    iid: _PositiveId
    body: Annotated[str, Field(min_length=1, max_length=60_000)]
    action_key: _ActionKey
    approved_plan_hash: _PlanHash
    position: DiffPosition | None = None


class ApproveMergeRequestArgs(ProjectRef):
    iid: _PositiveId
    sha: _Sha
    action_key: _ActionKey
    approved_plan_hash: _PlanHash


class ChangeVulnerabilityStateArgs(StrictModel):
    vulnerability_id: _PositiveId
    expected_state: _Status
    state: _Status
    action_key: _ActionKey
    approved_plan_hash: _PlanHash


class MergeMergeRequestArgs(ProjectRef):
    iid: _PositiveId
    sha: _Sha
    action_key: _ActionKey
    approved_plan_hash: _PlanHash


class PublishSecurityReportArtifactArgs(ProjectRef):
    iid: _PositiveId
    job_id: _PositiveId
    expected_head_sha: _Sha
    sarif: dict[str, Any]
    native_finding_uids: list[_FindingUid] = Field(max_length=5000)
    action_key: _ActionKey


class ControlPipelineArgs(ProjectRef):
    pipeline_id: _PositiveId
    operation: Literal["retry", "cancel"]
    expected_status: _Status
    action_key: _ActionKey


class ControlJobArgs(ProjectRef):
    job_id: _PositiveId
    operation: Literal["play", "retry", "cancel"]
    expected_status: _Status
    action_key: _ActionKey


class VendorResult(StrictModel):
    """A typed result retaining vendor-specific response data and coverage."""

    data: Any
    status_code: int = Field(default=200, ge=100, le=599)
    coverage: Literal["complete", "partial", "not_evaluated"] = "complete"
    dropped: list[dict[str, Any]] = Field(default_factory=list)


def _require_aware(value: datetime | None) -> datetime | None:
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise ValueError("timestamp must be timezone-aware")
    return value
