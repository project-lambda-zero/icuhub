"""F5 BIG-IP iControl models (MVP 4.18)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = [
    "MAX_IRULE_DEFINITION_BYTES",
    "BlockArgs",
    "BlockRecordResult",
    "CreateIruleArgs",
    "F5Config",
    "InventoryQuery",
    "Irule",
    "IruleListResult",
    "IruleQuery",
    "IruleResult",
    "UnblockArgs",
    "VirtualServersResult",
]

MAX_IRULE_DEFINITION_BYTES = 256 * 1024


def _safe_segment(value: str, field_name: str) -> str:
    if not value or value != value.strip() or value in (".", ".."):
        raise ValueError(f"{field_name} must be a non-empty normalized path segment")
    if any(char in "/\\~" or ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{field_name} must be one safe path segment")
    return value


class IruleQuery(BaseModel):
    """F5 iRule natural key: name, partition, and optional nested subPath."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    name: str = Field(min_length=1, max_length=255)
    partition: str = Field(default="Common", min_length=1, max_length=255)
    sub_path: str | None = Field(default=None, alias="subPath", min_length=1, max_length=1024)

    @field_validator("name", "partition")
    @classmethod
    def _safe_identity_segment(cls, value: str, info: ValidationInfo) -> str:
        return _safe_segment(value, info.field_name or "identity")

    @field_validator("sub_path")
    @classmethod
    def _safe_sub_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return "/".join(_safe_segment(segment, "subPath") for segment in value.split("/"))

    @property
    def expected_full_path(self) -> str:
        parts = [self.partition]
        if self.sub_path is not None:
            parts.extend(self.sub_path.split("/"))
        parts.append(self.name)
        return "/" + "/".join(parts)


class CreateIruleArgs(IruleQuery):
    """Create one iRule without updating an object that already exists."""

    definition: str = Field(alias="apiAnonymous", min_length=1)

    @field_validator("definition")
    @classmethod
    def _bounded_definition(cls, value: str) -> str:
        if len(value.encode("utf-8")) > MAX_IRULE_DEFINITION_BYTES:
            raise ValueError(f"apiAnonymous exceeds the {MAX_IRULE_DEFINITION_BYTES}-byte UTF-8 limit")
        return value


class Irule(IruleQuery):
    """An iRule as read from the vendor: identity plus the definition used for exact verification.

    Vendor responses carry many more keys than these; they are ignored. The definition is not
    byte-capped on read, so one oversized rule created outside ICUHUB cannot break a collection read.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True, strict=True)

    full_path: str = Field(alias="fullPath", min_length=1, max_length=2048)
    definition: str = Field(alias="apiAnonymous")
    definition_checksum: str | None = Field(default=None, alias="definitionChecksum", max_length=512)


class IruleResult(BaseModel):
    present: bool
    rule: Irule | None = None


class IruleListResult(BaseModel):
    items: list[Irule] = Field(default_factory=list)
    total: int = 0


class F5Config(ConnectorConfig):
    """iControl REST connection; credentials are exchanged for an X-F5-Auth-Token."""

    username: SecretRef
    password: SecretRef
    partition: str = "Common"
    #: The operator-managed internal data-group that ICUHUB owns entries in.
    data_group: str = "icuhub_blocked"
    #: Gates ``create_irule``. Off by default; reads and planning never depend on it.
    write_enabled: bool = False


class InventoryQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VirtualServersResult(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0


class BlockArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: str = Field(min_length=1, max_length=64, description="IP address or CIDR to block")
    ttl_s: int = Field(gt=0, le=365 * 86400)
    reason: str = Field(min_length=1, max_length=500)


class UnblockArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    block_id: str = Field(min_length=1, max_length=128)


class BlockRecordResult(BaseModel):
    block_id: str
    data_group: str
    generation: int | None = None
    record: dict[str, Any] | None = None
    present: bool
