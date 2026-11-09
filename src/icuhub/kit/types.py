"""Shared Pydantic contracts used by connectors and the host runtime."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

__all__ = [
    "ActionOutcome",
    "ActionPlan",
    "CapabilityHealth",
    "ConnectorConfig",
    "HealthReport",
    "ImportedFile",
    "MapContext",
    "RawBatch",
    "Scope",
    "SecretRef",
    "SourceRecord",
    "StreamRecord",
    "Target",
    "TargetRecord",
    "TicketRecord",
    "WebhookDelivery",
]


class SecretRef(BaseModel):
    """An opaque credential-broker reference, never secret material."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"writeOnly": True})

    ref: str = Field(min_length=1, json_schema_extra={"writeOnly": True})

    def __repr_args__(self) -> Any:
        yield "ref", "********"


class ConnectorConfig(BaseModel):
    """Common connection settings inherited by every connector config."""

    model_config = ConfigDict(extra="forbid")

    base_url: str
    ca_bundle_pem: str | None = None
    client_cert: SecretRef | None = None
    client_key: SecretRef | None = None
    proxy_url: str | None = None
    timeout_s: float = Field(default=30, gt=0)
    allow_plain_http_loopback: bool = False


class Scope(BaseModel):
    """A vendor permission and the probe that proves it."""

    name: str
    probe: str
    required_by: tuple[str, ...] = ()


class CapabilityHealth(BaseModel):
    """Health for one declared capability."""

    status: Literal["healthy", "degraded", "failing", "not_evaluated"]
    reason: str | None = None


class HealthReport(BaseModel):
    """Overall and per-capability connector health."""

    status: Literal["healthy", "degraded", "failing", "not_evaluated"]
    capabilities: dict[str, CapabilityHealth] = Field(default_factory=dict)
    vendor_version: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class TargetRecord(BaseModel):
    """A discovered target before the host assigns its identity."""

    source_uid: str
    kind: str
    display_name: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class Target(BaseModel):
    """A host-owned target passed to connector streams."""

    id: str
    source_uid: str
    kind: str
    display_name: str
    attributes: dict[str, Any]


class RawBatch(BaseModel):
    """Raw vendor records and the checkpoint proposed after durable commit."""

    records: list[dict[str, Any]]
    checkpoint: BaseModel | None
    complete: bool = False


class SourceRecord(BaseModel):
    """A normalized non-OCSF source object."""

    record_type: str
    uid: str
    revision: str | None = None
    data: dict[str, Any]
    links: dict[str, str] = Field(default_factory=dict)


class TicketRecord(SourceRecord):
    """Normalized tracker issue used for outbound ticket synchronization."""

    record_type: str = "ticket"
    key: str
    status: str
    status_category: Literal["open", "in_progress", "done", "unknown"]
    resolution: str | None = None
    url: str | None = None
    updated_at: datetime | None = None
    labels: list[str] = Field(default_factory=list)
    fingerprint_links: list[str] = Field(default_factory=list)


class StreamRecord(BaseModel):
    """A raw stream item emitted by a webhook parser."""

    stream: str
    raw: dict[str, Any]
    target_uid: str | None = None
    event: Literal["upsert", "delete"] = "upsert"


class WebhookDelivery(BaseModel):
    """Unmodified webhook bytes and normalized header names."""

    headers: dict[str, str]
    body: bytes
    received_at: datetime

    @field_validator("headers", mode="before")
    @classmethod
    def _lowercase_headers(cls, value: dict[str, str]) -> dict[str, str]:
        return {str(key).lower(): str(item) for key, item in value.items()}

    @model_validator(mode="after")
    def _aware_received_at(self) -> WebhookDelivery:
        if self.received_at.tzinfo is None or self.received_at.utcoffset() is None:
            raise ValueError("received_at must be timezone-aware")
        return self


class ActionPlan(BaseModel):
    """A deterministic, approval-ready description of a vendor write."""

    action: str
    target_ref: str
    diff: dict[str, Any]
    preconditions: dict[str, Any]
    idempotency_key: str
    changed: bool
    request: dict[str, Any]

    @computed_field
    @property
    def plan_hash(self) -> str:
        payload = {
            "action": self.action,
            "target_ref": self.target_ref,
            "diff": self.diff,
            "preconditions": self.preconditions,
            "idempotency_key": self.idempotency_key,
            "changed": self.changed,
            "request": self.request,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ActionOutcome(BaseModel):
    """Observable outcome of applying or reconciling an action plan."""

    status: Literal["succeeded", "no_op", "accepted_async", "outcome_unknown", "failed"]
    vendor_ref: str | None = None
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class MapContext(BaseModel):
    """Host identity and target context supplied to a pure mapper."""

    connection_id: str
    tenant_id: str
    connector_kind: str
    target: Target | None = None
    received_at: datetime


class ImportedFile(BaseModel):
    """An uploaded source file parsed without vendor network access."""

    filename: str
    media_type: str | None = None
    data: bytes
