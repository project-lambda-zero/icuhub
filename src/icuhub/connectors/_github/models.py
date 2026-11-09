"""Configuration and typed vendor inputs for the GitHub connector family."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from icuhub.kit.types import ConnectorConfig, SecretRef

_NAME = r"^[^/\s]+$"
_HEX_SHA = r"^[0-9a-fA-F]{7,64}$"
_ACTION_KEY = r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$"


class GitHubConfig(ConnectorConfig):
    """Shared GitHub App and PAT settings."""

    base_url: str = "https://api.github.com"
    api_version: str = "2022-11-28"
    personal_access_token: SecretRef | None = None
    app_id: str | None = None
    app_private_key: SecretRef | None = None
    installation_id: str | None = None
    organization: str | None = None
    enterprise: str | None = None
    probe_repository: str | None = None
    webhook_secret: SecretRef | None = None
    max_file_bytes: int = Field(default=256 * 1024, ge=1, le=4 * 1024 * 1024)
    max_repository_files: int = Field(default=1000, ge=1, le=10000)
    max_download_bytes: int = Field(default=8 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)
    max_sarif_bytes: int = Field(default=16 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)

    @field_validator("api_version")
    @classmethod
    def _api_date(cls, value: str) -> str:
        if re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", value) is None:
            raise ValueError("api_version must use YYYY-MM-DD")
        return value

    @field_validator("probe_repository")
    @classmethod
    def _probe_name(cls, value: str | None) -> str | None:
        if value is not None and len(value.split("/")) != 2:
            raise ValueError("probe_repository must use owner/repository")
        return value

    @model_validator(mode="after")
    def _one_auth_mode(self) -> GitHubConfig:
        app_values = (self.app_id, self.app_private_key, self.installation_id)
        app_complete = all(value is not None for value in app_values)
        if any(value is not None for value in app_values) and not app_complete:
            raise ValueError("app_id, app_private_key, and installation_id must be configured together")
        if app_complete == (self.personal_access_token is not None):
            raise ValueError("configure exactly one of GitHub App authentication or personal_access_token")
        return self


class VendorResult(BaseModel):
    """A typed result that retains vendor-specific response data."""

    model_config = ConfigDict(extra="forbid")

    data: dict[str, Any] = Field(default_factory=dict)
    text: str | None = None
    status_code: int


class EmptyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RepoRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner: str = Field(pattern=_NAME, max_length=100)
    repo: str = Field(pattern=_NAME, max_length=100)


class OrgRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization: str = Field(pattern=_NAME, max_length=100)


class EnterpriseRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enterprise: str = Field(pattern=_NAME, max_length=100)
    phrase: str | None = Field(default=None, max_length=1000)


class TeamRef(OrgRef):
    team_slug: str = Field(pattern=_NAME, max_length=100)


class MembershipRef(OrgRef):
    username: str = Field(pattern=_NAME, max_length=100)


class CollaboratorRef(RepoRef):
    username: str = Field(pattern=_NAME, max_length=100)


class BranchRef(RepoRef):
    branch: str = Field(min_length=1, max_length=255)


class TagRef(RepoRef):
    tag: str = Field(min_length=1, max_length=255)


class CommitRef(RepoRef):
    sha: str = Field(pattern=_HEX_SHA)


class TreeRef(RepoRef):
    tree_sha: str = Field(pattern=_HEX_SHA)
    recursive: bool = False


class FileRef(RepoRef):
    path: str = Field(min_length=1, max_length=4096)
    ref: str | None = Field(default=None, max_length=255)

    @field_validator("path")
    @classmethod
    def _safe_repository_path(cls, value: str) -> str:
        if value.startswith("/") or "\\" in value or any(part in ("", ".", "..") for part in value.split("/")):
            raise ValueError("path must be a normalized repository-relative file path")
        return value


class AlertRef(RepoRef):
    alert_number: int = Field(ge=1)


class AlertInstancesRef(AlertRef):
    ref: str | None = Field(default=None, max_length=255)


class AnalysisRef(RepoRef):
    analysis_id: int = Field(ge=1)


class PullRef(RepoRef):
    pull_number: int = Field(ge=1)


class ReviewRef(PullRef):
    review_id: int = Field(ge=1)


class ReviewCommentRef(RepoRef):
    comment_id: int = Field(ge=1)


class WorkflowRunRef(RepoRef):
    run_id: int = Field(ge=1)


class WorkflowJobRef(RepoRef):
    job_id: int = Field(ge=1)


class ArtifactRef(RepoRef):
    artifact_id: int = Field(ge=1)


class WebhookRef(RepoRef):
    hook_id: int = Field(ge=1)


class UploadSarifArgs(RepoRef):
    commit_sha: str = Field(pattern=_HEX_SHA)
    ref: str = Field(min_length=1, max_length=255)
    sarif: dict[str, Any]
    checkout_uri: str | None = None
    started_at: str | None = None
    tool_name: str | None = None
    validate: bool | None = None


class UpdateCodeScanningAlertArgs(AlertRef):
    state: Literal["open", "dismissed"]
    dismissed_reason: Literal["false positive", "used in tests", "won't fix"] | None = None
    dismissed_comment: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _dismissal_fields(self) -> UpdateCodeScanningAlertArgs:
        if self.state == "dismissed" and self.dismissed_reason is None:
            raise ValueError("dismissed_reason is required when dismissing an alert")
        if self.state == "open" and (self.dismissed_reason is not None or self.dismissed_comment is not None):
            raise ValueError("dismissal fields are valid only for dismissed alerts")
        return self


class CreatePrCommentArgs(PullRef):
    body: str = Field(min_length=1, max_length=60000)
    action_key: str = Field(pattern=_ACTION_KEY)


class ReviewComment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=4096)
    body: str = Field(min_length=1, max_length=60000)
    line: int | None = Field(default=None, ge=1)
    side: Literal["LEFT", "RIGHT"] | None = None
    start_line: int | None = Field(default=None, ge=1)
    start_side: Literal["LEFT", "RIGHT"] | None = None


class CreateReviewArgs(PullRef):
    event: Literal["APPROVE", "REQUEST_CHANGES", "COMMENT"]
    body: str | None = Field(default=None, max_length=60000)
    comments: list[ReviewComment] = Field(default_factory=list, max_length=100)


class CreatePullRequestArgs(RepoRef):
    title: str = Field(min_length=1, max_length=256)
    head: str = Field(min_length=1, max_length=255)
    base: str = Field(min_length=1, max_length=255)
    body: str | None = Field(default=None, max_length=60000)
    draft: bool = True
    maintainer_can_modify: bool | None = None


class CreateCommitStatusArgs(CommitRef):
    state: Literal["error", "failure", "pending", "success"]
    context: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=140)
    target_url: str | None = None


class CheckAnnotation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=4096)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_column: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=1)
    annotation_level: Literal["notice", "warning", "failure"]
    message: str = Field(min_length=1, max_length=64000)
    title: str | None = Field(default=None, max_length=255)
    raw_details: str | None = Field(default=None, max_length=64000)


class CheckRunArgs(CommitRef):
    name: str = Field(min_length=1, max_length=100)
    action_key: str = Field(pattern=_ACTION_KEY)
    status: Literal["queued", "in_progress", "completed"] = "completed"
    conclusion: Literal[
        "action_required", "cancelled", "failure", "neutral", "success", "skipped", "stale", "timed_out"
    ] | None = None
    title: str = Field(min_length=1, max_length=255)
    summary: str = Field(min_length=1, max_length=60000)
    text: str | None = Field(default=None, max_length=60000)
    details_url: str | None = None
    annotations: list[CheckAnnotation] = Field(default_factory=list, max_length=10000)

    @model_validator(mode="after")
    def _completed_conclusion(self) -> CheckRunArgs:
        if self.status == "completed" and self.conclusion is None:
            raise ValueError("conclusion is required for a completed check run")
        if self.status != "completed" and self.conclusion is not None:
            raise ValueError("conclusion is valid only for a completed check run")
        return self


class MergePullRequestArgs(PullRef):
    merge_method: Literal["merge", "squash", "rebase"] = "merge"
    expected_head_sha: str | None = Field(default=None, pattern=_HEX_SHA)
    commit_title: str | None = Field(default=None, max_length=256)
    commit_message: str | None = Field(default=None, max_length=60000)
