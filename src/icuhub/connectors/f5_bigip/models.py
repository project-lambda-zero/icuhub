"""F5 BIG-IP iControl models (MVP 4.18)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = ["BlockArgs", "BlockRecordResult", "F5Config", "InventoryQuery", "UnblockArgs", "VirtualServersResult"]


class F5Config(ConnectorConfig):
    """iControl REST connection; credentials are exchanged for an X-F5-Auth-Token."""

    username: SecretRef
    password: SecretRef
    partition: str = "Common"
    #: The operator-managed internal data-group that ICUHUB owns entries in.
    data_group: str = "icuhub_blocked"


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
