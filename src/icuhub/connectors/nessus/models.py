"""Configuration, operation contracts, and report record models for Nessus."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator

from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = [
    "CreateExportArgs",
    "DownloadExportArgs",
    "GetExportStatusArgs",
    "ListHistoryArgs",
    "ListScansArgs",
    "NessusConfig",
    "NessusExport",
    "NessusExportDownload",
    "NessusExportStatus",
    "NessusFindingRecord",
    "NessusHistory",
    "NessusHistoryList",
    "NessusHost",
    "NessusItem",
    "NessusReportContext",
    "NessusScan",
    "NessusScanDetail",
    "NessusScanList",
    "ScanDetailArgs",
]

_ID_PATTERN = r"^[A-Za-z0-9_.:-]+$"


class NessusConfig(ConnectorConfig):
    """Nessus connection settings. Export jobs are transient read-oriented jobs."""

    auth_mode: Literal["api_keys", "username_password_session"] = "api_keys"
    access_key: SecretRef | None = None
    secret_key: SecretRef | None = None
    username: str | None = Field(default=None, min_length=1, max_length=256)
    password: SecretRef | None = None
    export_timeout_s: float = Field(default=300, gt=0, le=3600)
    export_poll_interval_s: float = Field(default=0.5, ge=0, le=30)
    max_report_bytes: int = Field(default=64 * 1024 * 1024, ge=1024, le=256 * 1024 * 1024)
    max_report_items: int = Field(default=200_000, ge=1, le=1_000_000)
    max_report_hosts: int = Field(default=10_000, ge=1, le=100_000)
    max_depth: int = Field(default=64, ge=8, le=128)
    max_plugin_output_chars: int = Field(default=32_768, ge=256, le=1_048_576)

    @model_validator(mode="after")
    def _credentials_match_auth_mode(self) -> NessusConfig:
        if self.auth_mode == "api_keys":
            if self.access_key is None or self.secret_key is None:
                raise ValueError("api_keys auth requires access_key and secret_key")
            if self.username is not None or self.password is not None:
                raise ValueError("api_keys auth does not accept username or password")
        else:
            if self.username is None or self.password is None:
                raise ValueError("username_password_session auth requires username and password")
            if self.access_key is not None or self.secret_key is not None:
                raise ValueError("username_password_session auth does not accept API keys")
        return self


class NessusScan(BaseModel):
    """Vendor scan entry, retaining fields added by different Nessus editions."""

    model_config = ConfigDict(extra="allow")

    id: int | str
    name: str | None = None
    uuid: str | None = None
    schedule_uuid: str | None = None
    status: str | None = None
    folder_id: int | None = None
    last_modification_date: int | None = None


class NessusHistory(BaseModel):
    """One immutable history run. ``id`` is accepted for editions using that response spelling."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    history_id: int | str = Field(validation_alias=AliasChoices("history_id", "id"))
    time_start: int | None = None
    time_end: int | None = None
    status: str | None = None
    archived: bool | None = None
    uuid: str | None = None
    targets: Any = None
    incomplete_targets: Any = None


class NessusScanList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scans: list[NessusScan] = Field(default_factory=list)
    folders: list[dict[str, Any]] = Field(default_factory=list)


class NessusHistoryList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    history: list[NessusHistory] = Field(default_factory=list)
    total: int | None = None
    limit: int
    offset: int
    exclude_rollover: Literal[True] = True


class NessusScanDetail(BaseModel):
    model_config = ConfigDict(extra="allow")

    info: dict[str, Any] = Field(default_factory=dict)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    compliance: list[dict[str, Any]] = Field(default_factory=list)
    history: list[NessusHistory] = Field(default_factory=list)


class _ScanRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(min_length=1, max_length=128, pattern=_ID_PATTERN)


class ListScansArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    last_modification_date: int | None = Field(default=None, ge=0)
    folder_id: int | None = Field(default=None, ge=0)


class ListHistoryArgs(_ScanRef):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=1_000_000)
    sort: str | None = Field(default="time_end", pattern=r"^[A-Za-z_][A-Za-z0-9_:-]{0,63}$")
    exclude_rollover: Literal[True] = True


class ScanDetailArgs(_ScanRef):
    history_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=_ID_PATTERN)


class CreateExportArgs(_ScanRef):
    history_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=_ID_PATTERN)


class GetExportStatusArgs(_ScanRef):
    file_id: str = Field(min_length=1, max_length=256, pattern=_ID_PATTERN)
    export_kind: Literal["file", "token"] = "file"
    created_at: datetime | None = None
    poll_interval_s: float = Field(default=0.5, ge=0, le=30)
    timeout_s: float = Field(default=300, gt=0, le=3600)


class DownloadExportArgs(_ScanRef):
    file_id: str = Field(min_length=1, max_length=256, pattern=_ID_PATTERN)
    export_kind: Literal["file", "token"] = "file"
    created_at: datetime | None = None


class NessusExport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    history_id: str | None = None
    file_id: str
    export_kind: Literal["file", "token"]
    created_at: datetime
    expires_at: datetime


class NessusExportStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    ready: bool
    chunks_failed: list[int] = Field(default_factory=list)
    chunks_cancelled: list[int] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)


class NessusReportContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_uid: str
    report_name: str | None = None
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source: Literal["live", "upload"]
    scan_id: str | None = None
    history_id: str | None = None
    history_status: str | None = None
    archived: bool | None = None
    targets: Any = None
    incomplete_targets: Any = None
    targets_complete: bool | None = None


class NessusHost(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str
    name: str
    uid: str | None = None
    fqdn: str | None = None
    ip: str | None = None
    mac: str | None = None
    os: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    properties: dict[str, str] = Field(default_factory=dict)


class NessusItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ordinal: int = Field(ge=0)
    plugin_id: str
    plugin_name: str | None = None
    plugin_family: str | None = None
    severity: int | None = Field(default=None, ge=0, le=4)
    risk_factor: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    service: str | None = None
    synopsis: str | None = None
    description: str | None = None
    solution: str | None = None
    plugin_output: str = ""
    plugin_output_sha256: str | None = None
    plugin_output_size: int = 0
    truncated: bool = False
    output_bounded: bool = False
    cves: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    compliance: dict[str, str] = Field(default_factory=dict)
    attributes: dict[str, str] = Field(default_factory=dict)
    fields: dict[str, str] = Field(default_factory=dict)


class NessusFindingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_uid: str
    report: NessusReportContext
    host: NessusHost
    item: NessusItem


class NessusExportDownload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report: NessusReportContext
    records: list[NessusFindingRecord]
    file_sha256: str
    size_bytes: int
    truncated: bool
    output_bounded: bool
