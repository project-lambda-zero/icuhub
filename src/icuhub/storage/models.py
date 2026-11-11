"""PostgreSQL schema for the ICUHUB service (HLD section 4, MVP.md section 3).

Every tenant-scoped table carries ``tenant_id`` and is protected by row-level security
keyed on the ``app.tenant_id`` setting (migration ``0001``). Secrets never appear in
these tables in clear text: credentials are envelope-encrypted blobs, connection
configuration holds only ``SecretRef`` references, and raw vendor payloads are
encrypted before they are stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = [
    "TENANT_TABLES",
    "ActionPlanRow",
    "ActionRequest",
    "Approval",
    "AuditRecord",
    "Base",
    "CaseMember",
    "Connection",
    "CorrelationCase",
    "Credential",
    "EvidenceItem",
    "FileImport",
    "Finding",
    "Job",
    "Notification",
    "OutboxEvent",
    "PolicyRule",
    "QuarantineItem",
    "RawBatch",
    "ServiceAccount",
    "SourceRecord",
    "StreamState",
    "SyncRun",
    "Target",
    "Tenant",
    "TicketLink",
    "TicketRoute",
    "WebhookDelivery",
    "WebhookEndpoint",
]

_NAMING = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=_NAMING)
    type_annotation_map = {
        dict[str, Any]: JSONB,
        list[Any]: JSONB,
        uuid.UUID: UUID(as_uuid=True),
        datetime: DateTime(timezone=True),
        bytes: LargeBinary,
    }


def _pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _tenant() -> Mapped[uuid.UUID]:
    return mapped_column(ForeignKey("tenant.id", ondelete="CASCADE"), index=True)


def _created() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now())


class Tenant(Base):
    __tablename__ = "tenant"

    id: Mapped[uuid.UUID] = _pk()
    slug: Mapped[str] = mapped_column(String(63), unique=True)
    display_name: Mapped[str] = mapped_column(String(200))
    automation_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    created_at: Mapped[datetime] = _created()


class ServiceAccount(Base):
    """A caller identity: hashed API key or an OIDC subject, with roles."""

    __tablename__ = "service_account"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    name: Mapped[str] = mapped_column(String(200))
    key_prefix: Mapped[str | None] = mapped_column(String(16), unique=True)
    key_hash: Mapped[str | None] = mapped_column(String(64))
    oidc_issuer: Mapped[str | None] = mapped_column(Text)
    oidc_subject: Mapped[str | None] = mapped_column(Text)
    roles: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    groups: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    created_at: Mapped[datetime] = _created()
    disabled_at: Mapped[datetime | None]


class Credential(Base):
    """Envelope-encrypted secret (ADR-0006). ``SecretRef.ref`` is ``cred:<id>``."""

    __tablename__ = "credential"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    name: Mapped[str] = mapped_column(String(200))
    kek_id: Mapped[str] = mapped_column(String(200))
    dek_wrapped: Mapped[bytes]
    nonce: Mapped[bytes]
    ciphertext: Mapped[bytes]
    created_at: Mapped[datetime] = _created()
    rotated_at: Mapped[datetime | None]


class Connection(Base):
    __tablename__ = "connection"
    __table_args__ = (UniqueConstraint("tenant_id", "slug"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    kind: Mapped[str] = mapped_column(String(64))
    slug: Mapped[str] = mapped_column(String(63))
    display_name: Mapped[str] = mapped_column(String(200))
    config_json: Mapped[dict[str, Any]]
    egress_class: Mapped[str] = mapped_column(String(32), server_default=text("'vendor_tenant'"))
    allowed_operations: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    status: Mapped[str] = mapped_column(String(16), server_default=text("'active'"))
    last_health_at: Mapped[datetime | None]
    last_health_json: Mapped[dict[str, Any] | None]
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class Target(Base):
    __tablename__ = "target"
    __table_args__ = (UniqueConstraint("connection_id", "source_uid"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    source_uid: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(64))
    display_name: Mapped[str] = mapped_column(Text)
    attributes_json: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    included: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    paused: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    last_seen_at: Mapped[datetime | None]
    missing_since: Mapped[datetime | None]


class StreamState(Base):
    """Typed checkpoint and lease per (connection, target, stream, partition) (FR-ING-07)."""

    __tablename__ = "stream_state"
    __table_args__ = (UniqueConstraint("connection_id", "target_key", "stream", "partition"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("target.id", ondelete="CASCADE"))
    target_key: Mapped[str] = mapped_column(String(64), server_default=text("''"))
    stream: Mapped[str] = mapped_column(String(100))
    partition: Mapped[str] = mapped_column(String(200), server_default=text("''"))
    checkpoint_json: Mapped[dict[str, Any] | None]
    checkpoint_schema: Mapped[str | None] = mapped_column(String(200))
    version: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    lease_owner: Mapped[str | None] = mapped_column(String(200))
    lease_expires_at: Mapped[datetime | None]
    health: Mapped[str] = mapped_column(String(16), server_default=text("'not_evaluated'"))
    last_success_at: Mapped[datetime | None]
    last_full_at: Mapped[datetime | None]
    lag_s: Mapped[int | None] = mapped_column(Integer)
    interval_s: Mapped[int] = mapped_column(Integer, server_default=text("900"))
    full_interval_s: Mapped[int] = mapped_column(Integer, server_default=text("86400"))
    next_run_at: Mapped[datetime | None]
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))


class SyncRun(Base):
    __tablename__ = "sync_run"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    stream_state_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("stream_state.id", ondelete="CASCADE"))
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    stream: Mapped[str] = mapped_column(String(100))
    mode: Mapped[str] = mapped_column(String(16))
    completeness: Mapped[str] = mapped_column(String(16), server_default=text("'partial'"))
    outcome: Mapped[str] = mapped_column(String(16), server_default=text("'running'"))
    counts_json: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    error_class: Mapped[str | None] = mapped_column(String(100))
    error_detail: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = _created()
    finished_at: Mapped[datetime | None]


class RawBatch(Base):
    """Encrypted raw vendor payload with digest, for evidence and mapper replay (FR-NRM-07)."""

    __tablename__ = "raw_batch"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    sync_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sync_run.id", ondelete="SET NULL"))
    origin: Mapped[str] = mapped_column(String(16))  # stream | webhook | import | operation
    stream: Mapped[str] = mapped_column(String(100))
    digest: Mapped[str] = mapped_column(String(71))  # sha256:<hex>
    record_count: Mapped[int] = mapped_column(Integer)
    parser_version: Mapped[str] = mapped_column(String(32))
    kek_id: Mapped[str] = mapped_column(String(200))
    dek_wrapped: Mapped[bytes]
    nonce: Mapped[bytes]
    payload_enc: Mapped[bytes]
    created_at: Mapped[datetime] = _created()
    expires_at: Mapped[datetime]


class QuarantineItem(Base):
    __tablename__ = "quarantine_item"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    raw_batch_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("raw_batch.id", ondelete="CASCADE"))
    record_index: Mapped[int] = mapped_column(Integer)
    error_class: Mapped[str] = mapped_column(String(100))
    error_detail: Mapped[str] = mapped_column(Text)
    mapper_version: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = _created()
    replayed_at: Mapped[datetime | None]


class Finding(Base):
    """One source observation (FR-COR-01). Never merged with other observations."""

    __tablename__ = "finding"
    __table_args__ = (
        UniqueConstraint("connection_id", "stream", "source_uid"),
        Index("ix_finding_tenant_fingerprint", "tenant_id", "fingerprint"),
        Index("ix_finding_tenant_correlation_key", "tenant_id", "correlation_key"),
    )

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("target.id", ondelete="SET NULL"))
    stream: Mapped[str] = mapped_column(String(100))
    source_uid: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(67))
    ocsf_class_uid: Mapped[int] = mapped_column(Integer)
    severity_id: Mapped[int] = mapped_column(SmallInteger)
    status: Mapped[str] = mapped_column(String(32), server_default=text("'open'"))
    title: Mapped[str | None] = mapped_column(Text)
    ocsf_json: Mapped[dict[str, Any]]
    revision_digest: Mapped[str] = mapped_column(String(71))
    raw_batch_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("raw_batch.id", ondelete="SET NULL"))
    mapper_version: Mapped[int] = mapped_column(Integer)
    correlation_key: Mapped[str | None] = mapped_column(String(200))
    first_seen: Mapped[datetime] = _created()
    last_seen: Mapped[datetime] = _created()
    resolved_at: Mapped[datetime | None]


class SourceRecord(Base):
    """Non-OCSF typed record: inventory objects, tickets, GRC records, scan runs."""

    __tablename__ = "source_record"
    __table_args__ = (UniqueConstraint("connection_id", "record_type", "uid"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    stream: Mapped[str] = mapped_column(String(100))
    record_type: Mapped[str] = mapped_column(String(64))
    uid: Mapped[str] = mapped_column(Text)
    revision: Mapped[str | None] = mapped_column(Text)
    data_json: Mapped[dict[str, Any]]
    links_json: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    raw_batch_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("raw_batch.id", ondelete="SET NULL"))
    first_seen: Mapped[datetime] = _created()
    last_seen: Mapped[datetime] = _created()
    deleted_at: Mapped[datetime | None]


class CorrelationCase(Base):
    """Hub-owned logical remediation problem linking observations (FR-COR-01..03)."""

    __tablename__ = "correlation_case"
    __table_args__ = (
        Index(
            "uq_correlation_case_open_key",
            "tenant_id",
            "correlation_key",
            unique=True,
            postgresql_where=text("merged_into IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    correlation_key: Mapped[str] = mapped_column(String(200))
    key_version: Mapped[int] = mapped_column(SmallInteger)
    title: Mapped[str] = mapped_column(Text)
    severity_id: Mapped[int] = mapped_column(SmallInteger)
    detection_state: Mapped[str] = mapped_column(String(32), server_default=text("'open'"))
    remediation_state: Mapped[str] = mapped_column(String(32), server_default=text("'new'"))
    exception_state: Mapped[str] = mapped_column(String(32), server_default=text("'none'"))
    exception_expires_at: Mapped[datetime | None]
    exception_revision: Mapped[str | None] = mapped_column(Text)
    exception_scope_uids: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    merged_into: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("correlation_case.id"))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class CaseMember(Base):
    __tablename__ = "case_member"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("finding.id", ondelete="CASCADE"), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = _tenant()
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("correlation_case.id", ondelete="CASCADE"), index=True)
    reason: Mapped[str] = mapped_column(String(32))  # key_match | manual_merge | manual_split | own_case
    linked_by: Mapped[str] = mapped_column(String(200))
    linked_at: Mapped[datetime] = _created()


class EvidenceItem(Base):
    """Digest-addressed evidence manifest entry for a case (MVP.md section 3)."""

    __tablename__ = "evidence_item"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("correlation_case.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32))  # raw_batch | file_import | action_plan | approval | outcome
    digest: Mapped[str] = mapped_column(String(71))
    ref_table: Mapped[str] = mapped_column(String(64))
    ref_id: Mapped[uuid.UUID]
    created_at: Mapped[datetime] = _created()


class TicketRoute(Base):
    __tablename__ = "ticket_route"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    name: Mapped[str] = mapped_column(String(200))
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    action: Mapped[str] = mapped_column(String(100))  # tracker create action, e.g. create_issue
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    match_json: Mapped[dict[str, Any]]
    template_json: Mapped[dict[str, Any]]
    status_policy_json: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = _created()


class TicketLink(Base):
    """One external record per (route, case) (FR-COR-04)."""

    __tablename__ = "ticket_link"
    __table_args__ = (UniqueConstraint("tenant_id", "route_id", "case_id"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    route_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ticket_route.id", ondelete="CASCADE"))
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("correlation_case.id", ondelete="CASCADE"))
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    state: Mapped[str] = mapped_column(String(32), server_default=text("'pending'"))
    remote_key: Mapped[str | None] = mapped_column(Text)
    remote_id: Mapped[str | None] = mapped_column(Text)
    remote_url: Mapped[str | None] = mapped_column(Text)
    remote_status: Mapped[str | None] = mapped_column(Text)
    status_category: Mapped[str | None] = mapped_column(String(16))
    last_outbound_revision: Mapped[str | None] = mapped_column(Text)
    last_inbound_revision: Mapped[str | None] = mapped_column(Text)
    last_synced_at: Mapped[datetime | None]
    action_request_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("action_request.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = _created()


class PolicyRule(Base):
    __tablename__ = "policy_rule"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    priority: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(200))
    match_json: Mapped[dict[str, Any]]
    decision: Mapped[str] = mapped_column(String(24))  # allow | deny | require_approval | preview
    auto_execute_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    approver_group: Mapped[str | None] = mapped_column(String(200))
    approval_ttl_s: Mapped[int] = mapped_column(Integer, server_default=text("86400"))
    created_at: Mapped[datetime] = _created()


ACTION_ACTIVE_STATES: tuple[str, ...] = (
    "received",
    "pending_approval",
    "approved",
    "executing",
    "accepted_async",
    "outcome_unknown",
)


class ActionRequest(Base):
    __tablename__ = "action_request"
    __table_args__ = (
        UniqueConstraint("tenant_id", "caller_id", "idempotency_key"),
        Index(
            "uq_action_request_natural_key_active",
            "tenant_id",
            "connection_id",
            "action",
            "natural_key",
            unique=True,
            postgresql_where=text(
                "natural_key IS NOT NULL AND state IN ("
                + ", ".join(f"'{state}'" for state in ACTION_ACTIVE_STATES)
                + ")"
            ),
        ),
    )

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    action: Mapped[str] = mapped_column(String(100))
    classification: Mapped[str] = mapped_column(String(16))
    args_json: Mapped[dict[str, Any]]
    args_digest: Mapped[str] = mapped_column(String(71))
    caller_id: Mapped[str] = mapped_column(String(200))
    correlation_id: Mapped[str | None] = mapped_column(String(200))
    idempotency_key: Mapped[str] = mapped_column(String(200))
    natural_key: Mapped[str | None] = mapped_column(String(200))
    mode: Mapped[str] = mapped_column(String(16), server_default=text("'live'"))
    state: Mapped[str] = mapped_column(String(24))
    decision: Mapped[str | None] = mapped_column(String(24))
    rule_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("policy_rule.id", ondelete="SET NULL"))
    result_json: Mapped[dict[str, Any] | None]
    error_class: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class ActionPlanRow(Base):
    __tablename__ = "action_plan"

    action_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("action_request.id", ondelete="CASCADE"), primary_key=True
    )
    tenant_id: Mapped[uuid.UUID] = _tenant()
    target_ref: Mapped[str] = mapped_column(Text)
    diff_json: Mapped[dict[str, Any]]
    preconditions_json: Mapped[dict[str, Any]]
    request_json: Mapped[dict[str, Any]]
    idempotency_key: Mapped[str] = mapped_column(String(200))
    plan_hash: Mapped[str] = mapped_column(String(71))
    changed: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = _created()


class Approval(Base):
    __tablename__ = "approval"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    action_request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("action_request.id", ondelete="CASCADE"))
    approver_group: Mapped[str | None] = mapped_column(String(200))
    plan_hash: Mapped[str] = mapped_column(String(71))
    expires_at: Mapped[datetime]
    decision: Mapped[str | None] = mapped_column(String(16))  # approved | rejected | expired
    decided_by: Mapped[str | None] = mapped_column(String(200))
    decided_at: Mapped[datetime | None]
    reason: Mapped[str | None] = mapped_column(Text)
    change_ref: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _created()


class AuditRecord(Base):
    """Hash-chained audit per tenant: ``hash = H(prev_hash || canonical(record))`` (FR-AUD-02)."""

    __tablename__ = "audit_record"
    __table_args__ = (UniqueConstraint("tenant_id", "seq"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    seq: Mapped[int] = mapped_column(BigInteger)
    prev_hash: Mapped[str] = mapped_column(String(71))
    hash: Mapped[str] = mapped_column(String(71))
    ts: Mapped[datetime]
    caller_id: Mapped[str] = mapped_column(String(200))
    connection_id: Mapped[uuid.UUID | None]
    operation: Mapped[str] = mapped_column(String(200))
    classification: Mapped[str | None] = mapped_column(String(16))
    decision: Mapped[str | None] = mapped_column(String(24))
    approval_id: Mapped[uuid.UUID | None]
    args_digest: Mapped[str | None] = mapped_column(String(71))
    status: Mapped[str] = mapped_column(String(32))
    correlation_id: Mapped[str | None] = mapped_column(String(200))
    detail_json: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))


class WebhookEndpoint(Base):
    """Random, unguessable ingress endpoint with dual-secret rotation (FR-CON-08)."""

    __tablename__ = "webhook_endpoint"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = _tenant()
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    secret_ref: Mapped[str] = mapped_column(String(200))
    previous_secret_ref: Mapped[str | None] = mapped_column(String(200))
    previous_valid_until: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created()
    disabled_at: Mapped[datetime | None]


class WebhookDelivery(Base):
    __tablename__ = "webhook_delivery"
    __table_args__ = (UniqueConstraint("connection_id", "vendor_delivery_id"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("webhook_endpoint.id", ondelete="CASCADE"))
    vendor_delivery_id: Mapped[str] = mapped_column(String(200))
    event_type: Mapped[str | None] = mapped_column(String(200))
    raw_batch_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("raw_batch.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(16), server_default=text("'received'"))
    error: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime] = _created()
    processed_at: Mapped[datetime | None]


class FileImport(Base):
    __tablename__ = "file_import"
    __table_args__ = (UniqueConstraint("connection_id", "importer", "digest"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    importer: Mapped[str] = mapped_column(String(100))
    filename: Mapped[str] = mapped_column(Text)
    digest: Mapped[str] = mapped_column(String(71))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    state: Mapped[str] = mapped_column(String(16), server_default=text("'queued'"))
    raw_batch_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("raw_batch.id", ondelete="SET NULL"))
    counts_json: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _created()
    finished_at: Mapped[datetime | None]


class Job(Base):
    """Postgres ``SKIP LOCKED`` job queue with leases (ADR-0014)."""

    __tablename__ = "job"
    __table_args__ = (
        Index("ix_job_claim", "queue", "state", "run_at"),
        Index("uq_job_dedupe_active", "dedupe_key", unique=True,
              postgresql_where=text("state IN ('queued', 'running')")),
    )

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenant.id", ondelete="CASCADE"))
    queue: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[dict[str, Any]]
    priority: Mapped[int] = mapped_column(SmallInteger, server_default=text("100"))
    run_at: Mapped[datetime] = mapped_column(server_default=func.now())
    attempts: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    max_attempts: Mapped[int] = mapped_column(Integer, server_default=text("5"))
    state: Mapped[str] = mapped_column(String(16), server_default=text("'queued'"))
    lease_id: Mapped[uuid.UUID | None]
    lease_owner: Mapped[str | None] = mapped_column(String(200))
    lease_expires_at: Mapped[datetime | None]
    dedupe_key: Mapped[str | None] = mapped_column(String(300))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class OutboxEvent(Base):
    __tablename__ = "outbox_event"
    __table_args__ = (Index("ix_outbox_event_pending", "relayed_at", "created_at"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    event_id: Mapped[str] = mapped_column(String(200), unique=True)
    topic: Mapped[str] = mapped_column(String(249))
    event_json: Mapped[dict[str, Any]]
    created_at: Mapped[datetime] = _created()
    relayed_at: Mapped[datetime | None]
    attempts: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    last_error: Mapped[str | None] = mapped_column(Text)


class Notification(Base):
    __tablename__ = "notification"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("connection.id", ondelete="CASCADE"))
    template: Mapped[str] = mapped_column(String(100))
    recipients: Mapped[list[str]] = mapped_column(ARRAY(Text))
    subject: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(16), server_default=text("'queued'"))
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _created()
    sent_at: Mapped[datetime | None]


TENANT_TABLES: tuple[str, ...] = tuple(
    sorted(t.name for t in Base.metadata.sorted_tables if "tenant_id" in t.c and t.name != "job")
)
"""Tables under row-level security. ``job`` is excluded: workers claim across tenants and
set ``app.tenant_id`` from the claimed job before touching tenant data."""
