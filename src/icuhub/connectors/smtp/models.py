"""SMTP notifier connector models (MVP 4.20)."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = ["SendNotificationArgs", "SmtpConfig"]

_ADDRESS = re.compile(r"^[^@\s]+@[^@\s]+$")


class SmtpConfig(ConnectorConfig):
    """Outbound SMTP connection. TLS certificate verification is always enabled."""

    base_url: str = ""
    host: str = Field(min_length=1)
    port: int = Field(default=587, ge=1, le=65535)
    security: Literal["starttls", "ssl"] = "starttls"
    username: SecretRef | None = None
    password: SecretRef | None = None
    from_address: str = Field(min_length=3)
    #: Exact addresses or ``*@domain`` patterns. Empty means no recipient restriction.
    allowed_recipients: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _fill_base_url(self) -> SmtpConfig:
        if not self.base_url:
            self.base_url = f"smtp://{self.host}:{self.port}"
        if not _ADDRESS.match(self.from_address):
            raise ValueError("from_address must be an email address")
        if (self.username is None) != (self.password is None):
            raise ValueError("username and password must be configured together")
        return self

    def recipient_allowed(self, address: str) -> bool:
        if not self.allowed_recipients:
            return True
        domain = address.rsplit("@", 1)[-1].lower()
        return any(
            address.lower() == pattern.lower() or (pattern.startswith("*@") and domain == pattern[2:].lower())
            for pattern in self.allowed_recipients
        )


class SendNotificationArgs(BaseModel):
    """The ``send_notification`` action input used by core.notifier."""

    model_config = ConfigDict(extra="forbid")

    recipients: list[str] = Field(min_length=1)
    subject: str = Field(min_length=1, max_length=998)
    body: str = Field(min_length=1, max_length=200_000)
    template: str | None = None

    @model_validator(mode="after")
    def _valid_addresses(self) -> SendNotificationArgs:
        for address in self.recipients:
            if not _ADDRESS.match(address):
                raise ValueError(f"invalid recipient address: {address!r}")
        return self
