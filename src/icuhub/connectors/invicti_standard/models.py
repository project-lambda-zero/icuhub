"""Configuration and typed I/O for Invicti Standard report ingestion."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from icuhub.connectors._invicti.reports import DEFAULT_MAX_REPORT_BYTES, InvictiReport
from icuhub.kit.types import ConnectorConfig

__all__ = ["InvictiStandardConfig", "ParseReportArgs", "ParseReportOutput"]


class InvictiStandardConfig(ConnectorConfig):
    base_url: str = ""
    website_id: str | None = None
    website_name: str | None = None
    report_files: tuple[str, ...] = ()
    max_report_bytes: int = Field(default=DEFAULT_MAX_REPORT_BYTES, ge=1, le=DEFAULT_MAX_REPORT_BYTES)
    max_report_files: int = Field(default=16, ge=1, le=128)
    webhook_mode: Literal["static_header", "basic_auth"] = "static_header"
    webhook_header: str = Field(default="x-icuhub-token", min_length=1)
    webhook_configuration_revision: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def _local_file_contract(self) -> InvictiStandardConfig:
        if len(self.report_files) > self.max_report_files:
            raise ValueError("report_files exceeds max_report_files")
        return self


class ParseReportArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content_base64: str
    profile: Literal["invicti_json"] = "invicti_json"


class ParseReportOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report: InvictiReport
