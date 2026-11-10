"""Archer GRC configuration, reference, and I/O models."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from icuhub.kit import ConnectorConfig, SecretRef

__all__ = [
    "ApplicationRef",
    "ArcherConfig",
    "ArcherContent",
    "ArcherItem",
    "ArcherRecordTypeMap",
    "AttachmentOutput",
    "AttachmentRef",
    "ContentOutput",
    "ContentRef",
    "CreateFindingOrExceptionInput",
    "DataFeedHistoryOutput",
    "DeleteContentInput",
    "DiscoverOutput",
    "EmptyInput",
    "ExecuteDataFeedInput",
    "HistoryOutput",
    "ItemsOutput",
    "LevelRef",
    "SearchContentArgs",
    "SearchContentOutput",
    "UpdateFindingOrExceptionInput",
    "UploadAttachmentInput",
    "ValuesListRef",
    "VersionOutput",
]


class ArcherRecordTypeMap(BaseModel):
    """Maps one logical Archer record type to its application, level, and fields."""

    model_config = ConfigDict(extra="forbid")

    application_id: int = Field(ge=1)
    level_id: int = Field(ge=1)
    field_ids: dict[str, int] = Field(default_factory=dict)
    correlation_field: str | None = None
    time_field: str | None = None  # defaults to LastUpdated [UNVERIFIED field name]


class ArcherConfig(ConnectorConfig):
    """Archer on-prem or SaaS connection configuration."""

    instance_name: str = Field(min_length=1)
    auth_mode: Literal["session", "domain_session"] = "session"
    user: str = Field(min_length=1)
    user_domain: str | None = None
    password: SecretRef
    record_types: dict[str, ArcherRecordTypeMap] = Field(default_factory=dict)
    page_size: int = Field(100, ge=1, le=1000)
    max_pages: int = Field(10_000, ge=1, le=100_000)
    attachment_max_bytes: int = Field(16 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)
    write_enabled: bool = False
    destructive_enabled: bool = False

    @model_validator(mode="after")
    def _domain_required(self) -> "ArcherConfig":
        if self.auth_mode == "domain_session" and not self.user_domain:
            raise ValueError("user_domain is required when auth_mode is domain_session")
        return self


class ArcherItem(BaseModel):
    """One metadata entity (application, level, field, values-list value)."""

    id: int
    name: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class ItemsOutput(BaseModel):
    items: list[ArcherItem]


class VersionOutput(BaseModel):
    version: str
    raw: dict[str, Any] = Field(default_factory=dict)


class ApplicationRef(BaseModel):
    application_id: int = Field(ge=1)


class LevelRef(BaseModel):
    level_id: int = Field(ge=1)


class ValuesListRef(BaseModel):
    values_list_id: int = Field(ge=1)


class ContentRef(BaseModel):
    content_id: int = Field(ge=1)


class AttachmentRef(BaseModel):
    attachment_id: int = Field(ge=1)


class SearchContentArgs(BaseModel):
    level_id: int = Field(ge=1)
    page_number: int = Field(1, ge=1)
    page_size: int = Field(100, ge=1, le=1000)


class SearchContentOutput(BaseModel):
    records: list[ArcherItem]
    page_number: int
    has_more: bool


class ArcherContent(BaseModel):
    content_id: int
    level_id: int | None = None
    version: int | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class ContentOutput(BaseModel):
    content: ArcherContent


class HistoryOutput(BaseModel):
    entries: list[dict[str, Any]]


class AttachmentOutput(BaseModel):
    attachment_id: int
    size_bytes: int
    sha256: str
    content_base64: str


class DataFeedHistoryOutput(BaseModel):
    runs: list[dict[str, Any]]


class DiscoverOutput(BaseModel):
    available: bool
    status: int


class EmptyInput(BaseModel):
    """Input for operations that take no arguments."""


class CreateFindingOrExceptionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record_type: str = Field(min_length=1)
    correlation_value: str = Field(min_length=1)
    field_values: dict[str, Any] = Field(default_factory=dict)


class UpdateFindingOrExceptionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record_type: str = Field(min_length=1)
    content_id: int = Field(ge=1)
    expected_version: int = Field(ge=0)
    field_values: dict[str, Any] = Field(default_factory=dict)


class UploadAttachmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record_type: str = Field(min_length=1)
    content_id: int = Field(ge=1)
    field_name: str = Field(min_length=1)
    filename: str = Field(min_length=1)
    content_base64: str = Field(min_length=1)
    expected_version: int = Field(ge=0)


class ExecuteDataFeedInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_feed_guid: str = Field(min_length=1)
    approved_plan_hash: str = Field(min_length=1)
    include_reference_feeds: bool = False


class DeleteContentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content_id: int = Field(ge=1)
    level_id: int = Field(ge=1)
    expected_version: int = Field(ge=0)
    approved_plan_hash: str = Field(min_length=1)
