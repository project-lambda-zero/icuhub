"""Typed configuration and lookup contracts for Google Threat Intelligence API v3."""

from __future__ import annotations

import re
from ipaddress import ip_address
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = ["GoogleThreatIntelligenceConfig", "Indicator", "IntelReport"]

_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")


class GoogleThreatIntelligenceConfig(ConnectorConfig):
    """Connection settings for the native Google Threat Intelligence REST API."""

    base_url: str = "https://www.virustotal.com/api/v3"
    api_key: SecretRef


class Indicator(BaseModel):
    """An indicator whose explicit kind determines the API v3 lookup endpoint."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["file", "url", "domain", "ip"]
    value: str = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_indicator(self) -> Indicator:
        if self.value != self.value.strip():
            raise ValueError("indicator value must not have surrounding whitespace")
        if self.kind == "file":
            if _SHA256.fullmatch(self.value) is None:
                raise ValueError("file indicator value must be a 64-character SHA-256 hexadecimal digest")
            self.value = self.value.lower()
        elif self.kind == "ip":
            try:
                ip_address(self.value)
            except ValueError:
                raise ValueError("ip indicator value must be a valid IPv4 or IPv6 address") from None
        elif self.kind == "domain" and any(char in self.value for char in ("/", "\\", "?", "#")):
            raise ValueError("domain indicator value must be one domain name")
        return self


class IntelReport(BaseModel):
    """A vendor report with source attributes and unmodified analysis counts."""

    model_config = ConfigDict(extra="forbid")

    id: str
    type: str
    attributes: dict[str, Any]
    stats: dict[str, int] | None
