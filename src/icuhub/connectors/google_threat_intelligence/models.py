"""Google Threat Intelligence (VirusTotal API v3) lookup models (MVP 4.19)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = ["GtiConfig", "Indicator", "IntelReport"]


class GtiConfig(ConnectorConfig):
    base_url: str = "https://www.virustotal.com/api/v3"
    api_key: SecretRef


class Indicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["file", "url", "domain", "ip"]
    value: str = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def _shape(self) -> Indicator:
        value = self.value.strip()
        if self.type == "file" and not all(c in "0123456789abcdefABCDEF" for c in value):
            raise ValueError("file indicators must be a hex hash")
        if self.type in ("domain", "ip") and any(c in value for c in "/ ?#"):
            raise ValueError(f"invalid {self.type} indicator")
        return self


class IntelReport(BaseModel):
    """Normalized synchronous verdict; no stream is implied."""

    indicator: str
    type: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0
    reputation: int | None = None
    last_analysis_date: int | None = None
    categories: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    reference: str | None = None

    @property
    def verdict(self) -> str:
        if self.malicious:
            return "malicious"
        if self.suspicious:
            return "suspicious"
        if self.harmless:
            return "harmless"
        return "unknown"
