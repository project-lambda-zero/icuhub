"""Typed configuration and operations for Invicti Enterprise REST API 1.0."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from icuhub.connectors._invicti.evidence import ProofEvidence
from icuhub.connectors._invicti.records import InvictiIssue, InvictiScan, InvictiScanResult, InvictiWebsite
from icuhub.connectors._invicti.reports import DEFAULT_MAX_REPORT_BYTES, InvictiReport
from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = [
    "DownloadReportArgs",
    "EmptyArgs",
    "InvictiEnterpriseConfig",
    "IssueArgs",
    "IssueHistoryOutput",
    "IssueListOutput",
    "IssueOutput",
    "ListIssuesArgs",
    "ListScansArgs",
    "NotificationListOutput",
    "NotificationView",
    "ReportOutput",
    "ScanArgs",
    "ScanListOutput",
    "ScanResultOutput",
    "ScanViewOutput",
    "UpdateIssueInput",
    "WebsiteArgs",
    "WebsiteOutput",
]


class InvictiEnterpriseConfig(ConnectorConfig):
    user_id: str = Field(min_length=1)
    api_token: SecretRef
    page_size: int = Field(default=200, ge=1, le=200)
    overlap_s: int = Field(default=300, ge=0, le=86400)
    max_tie_ids: int = Field(default=10000, ge=100, le=100000)
    max_report_bytes: int = Field(default=DEFAULT_MAX_REPORT_BYTES, ge=1, le=DEFAULT_MAX_REPORT_BYTES)
    webhook_mode: Literal["static_header", "basic_auth"] = "static_header"
    webhook_header: str = Field(default="x-icuhub-token", min_length=1)
    webhook_integration_id: str = Field(default="default", min_length=1)
    webhook_configuration_revision: int = Field(default=1, ge=1)


class ListIssuesArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    last_seen_start: datetime | None = None
    last_seen_end: datetime | None = None
    website_id: str | None = None
    severity: str | None = None
    source_type: str | None = None
    sort: Literal["asc", "desc"] = "asc"
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=200, ge=1, le=200)


class ListScansArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    initiated_start: datetime | None = None
    initiated_end: datetime | None = None
    state_changed_start: datetime | None = None
    state_changed_end: datetime | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=200, ge=1, le=200)

    @model_validator(mode="after")
    def _complete_windows(self) -> ListScansArgs:
        if (self.state_changed_start is None) != (self.state_changed_end is None):
            raise ValueError("state_changed_start and state_changed_end must be supplied together")
        return self


class IssueListOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issues: list[InvictiIssue]
    page: int
    has_next: bool


class ScanListOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scans: list[InvictiScan]
    page: int
    has_next: bool


class IssueArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issue_id: str = Field(min_length=1)


class WebsiteArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    website_id: str = Field(min_length=1)


class ScanArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: str = Field(min_length=1)


class EmptyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IssueOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issue: InvictiIssue
    evidence: ProofEvidence


class IssueHistoryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    history: list[dict]


class WebsiteOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    website: InvictiWebsite
    groups: list[str]


class ScanViewOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan: InvictiScan


class ScanResultOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    results: list[InvictiScanResult]


class DownloadReportArgs(ScanArgs):
    report_type: str = Field(default="InvictiJson", min_length=1)


class ReportOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report: InvictiReport
    evidence: dict[str, ProofEvidence]


class NotificationView(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str | None = None
    event: str | None = None
    scope: str | None = None


class NotificationListOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    notifications: list[NotificationView]


class UpdateIssueInput(IssueArgs):
    expected_last_seen: datetime
    expected_state: str = Field(min_length=1)
    state: str | None = None
    assignee: str | None = None
    tags: list[str] | None = None

    @model_validator(mode="after")
    def _desired_change(self) -> UpdateIssueInput:
        if self.state is None and self.assignee is None and self.tags is None:
            raise ValueError("at least one desired issue field is required")
        return self
