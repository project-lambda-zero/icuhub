"""Process configuration.

This module is the only reader of ``ICUHUB_*`` environment variables. Secret
values are referenced by name through :class:`icuhub.kit.types.SecretRef`; the
secret material itself never lives in settings.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from icuhub.kit.types import SecretRef

__all__ = ["ENV_PREFIX", "Settings", "get_settings"]

ENV_PREFIX = "ICUHUB_"

_SECRET_REF_FIELDS = frozenset(
    {
        "kafka_sasl_username_ref",
        "kafka_sasl_password_ref",
        "smtp_username_ref",
        "smtp_password_ref",
    }
)


class Settings(BaseModel):
    """Typed process configuration loaded from ``ICUHUB_<FIELD>`` variables."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    database_url: str | None = None
    automation_enabled: bool = False
    worker_concurrency: int = Field(default=4, ge=1)
    raw_retention_days: int = Field(default=30, ge=1)
    webhook_max_body_bytes: int = Field(default=10485760, ge=1)
    webhook_rotation_window_s: int = Field(default=300, ge=0)
    public_base_url: str | None = None
    evidence_signing_key_file: Path | None = None
    evidence_verification_key_file: Path | None = None

    kek_provider: Literal["file", "openbao"] = "file"
    kek_file_path: Path | None = None
    openbao_url: str | None = None
    openbao_token_file: Path | None = None
    openbao_transit_key: str | None = None

    kafka_bootstrap: str | None = None
    kafka_topic_prefix: str = "icuhub"
    kafka_security: Literal["plaintext", "ssl", "sasl_ssl"] = "plaintext"
    kafka_ca_file: Path | None = None
    kafka_sasl_mechanism: str | None = None
    kafka_sasl_username_ref: SecretRef | None = None
    kafka_sasl_password_ref: SecretRef | None = None
    relay_batch_size: int = Field(default=100, ge=1)

    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None

    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_from: str | None = None
    smtp_username_ref: SecretRef | None = None
    smtp_password_ref: SecretRef | None = None


def _read_environment(environ: Mapping[str, str]) -> dict[str, object]:
    """Collect set ``ICUHUB_*`` variables; empty values fall back to field defaults."""
    values: dict[str, object] = {}
    for name in Settings.model_fields:
        raw = environ.get(f"{ENV_PREFIX}{name.upper()}")
        if not raw:
            continue
        values[name] = SecretRef(ref=raw) if name in _SECRET_REF_FIELDS else raw
    return values


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process settings, parsed once from the environment."""
    return Settings.model_validate(_read_environment(os.environ))
