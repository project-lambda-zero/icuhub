"""Append-only, per-tenant audit hash chains (FR-AUD-02 and FR-AUD-05).

Hash rule: ``hash = "sha256:" + hex(SHA-256(prev_hash + canonical_json(fields)))``
where ``fields`` is the explicit map built by ``_canonical_fields``. The genesis
``prev_hash`` of each tenant chain is ``"sha256:" + 64 zeros``.

Purge rule: an empty ``detail_json`` is reserved as the FR-AUD-05 purge marker, so
``append`` refuses empty detail. A purged row keeps its stored hash and chain link;
its erased detail cannot be recomputed, so ``verify_chain`` validates the stored
hash format and the links around it but cannot detect edits to its other fields.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.storage.models import AuditRecord

__all__ = ["AuditFailure", "VerifyResult", "append", "verify_chain"]

GENESIS_PREV_HASH = "sha256:" + "0" * 64
_HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class AuditFailure:
    """One integrity failure located by sequence number and record identifier."""

    seq: int
    record_id: uuid.UUID
    reason: str


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Verification outcome: ``ok`` is true only when ``failures`` is empty."""

    ok: bool
    checked: int
    failures: tuple[AuditFailure, ...]


def _canonical_timestamp(value: datetime) -> str:
    if value.utcoffset() is None:
        raise ValueError("audit timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _canonical_fields(record: AuditRecord) -> str:
    """Serialize every semantic column explicitly; only ``prev_hash`` and ``hash`` are excluded."""

    fields: dict[str, Any] = {
        "id": str(record.id),
        "tenant_id": str(record.tenant_id),
        "seq": record.seq,
        "ts": _canonical_timestamp(record.ts),
        "caller_id": record.caller_id,
        "connection_id": None if record.connection_id is None else str(record.connection_id),
        "operation": record.operation,
        "classification": record.classification,
        "decision": record.decision,
        "approval_id": None if record.approval_id is None else str(record.approval_id),
        "args_digest": record.args_digest,
        "status": record.status,
        "correlation_id": record.correlation_id,
        "detail_json": record.detail_json,
    }
    return json.dumps(
        fields,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _record_hash(record: AuditRecord, prev_hash: str) -> str:
    digest = hashlib.sha256((prev_hash + _canonical_fields(record)).encode("utf-8"))
    return "sha256:" + digest.hexdigest()


def _lock_key(tenant_id: uuid.UUID) -> int:
    return int.from_bytes(tenant_id.bytes[:8], byteorder="big", signed=True)


async def append(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    ts: datetime,
    caller_id: str,
    operation: str,
    status: str,
    detail_json: dict[str, Any],
    connection_id: uuid.UUID | None = None,
    classification: str | None = None,
    decision: str | None = None,
    approval_id: uuid.UUID | None = None,
    args_digest: str | None = None,
    correlation_id: str | None = None,
) -> AuditRecord:
    """Append one record to the tenant chain inside the caller's transaction.

    A transaction-scoped advisory lock serializes appends per tenant until the
    caller commits, so ``seq = max(seq) + 1`` and the previous hash are read and
    written without a concurrent writer splitting the chain.

    Raises:
        ValueError: ``detail_json`` is empty (reserved as the purge marker) or
            ``ts`` is naive.
    """

    if not detail_json:
        raise ValueError("audit detail_json must be non-empty; {} is the purge marker")
    _canonical_timestamp(ts)  # rejects naive timestamps before any row is written
    await session.execute(
        text("SELECT pg_advisory_xact_lock(CAST(:lock_key AS bigint))"),
        {"lock_key": _lock_key(tenant_id)},
    )
    previous = (
        await session.execute(
            select(AuditRecord.seq, AuditRecord.hash)
            .where(AuditRecord.tenant_id == tenant_id)
            .order_by(AuditRecord.seq.desc())
            .limit(1)
        )
    ).first()
    seq = 1 if previous is None else previous.seq + 1
    prev_hash = GENESIS_PREV_HASH if previous is None else previous.hash
    record = AuditRecord(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        seq=seq,
        prev_hash=prev_hash,
        hash=GENESIS_PREV_HASH,
        ts=ts,
        caller_id=caller_id,
        connection_id=connection_id,
        operation=operation,
        classification=classification,
        decision=decision,
        approval_id=approval_id,
        args_digest=args_digest,
        status=status,
        correlation_id=correlation_id,
        detail_json=detail_json,
    )
    record.hash = _record_hash(record, prev_hash)
    session.add(record)
    await session.flush()
    return record


async def verify_chain(session: AsyncSession, tenant_id: uuid.UUID) -> VerifyResult:
    """Check every retained record of a tenant in sequence order.

    For each row the verifier checks that ``seq`` is the next expected value,
    that ``prev_hash`` equals the previous stored hash (or genesis), and that the
    hash is correct. Unpurged rows are rehashed from their fields. Purged rows
    (``detail_json == {}``) are checked for a well-formed stored hash only. Every
    failure is reported; a gap does not stop the scan.
    """

    records = (
        (
            await session.execute(
                select(AuditRecord)
                .where(AuditRecord.tenant_id == tenant_id)
                .order_by(AuditRecord.seq)
            )
        )
        .scalars()
        .all()
    )
    failures: list[AuditFailure] = []
    expected_seq = 1
    expected_prev_hash = GENESIS_PREV_HASH
    for record in records:
        if record.seq != expected_seq:
            failures.append(
                AuditFailure(
                    seq=record.seq,
                    record_id=record.id,
                    reason=f"sequence gap: expected seq {expected_seq}, found {record.seq}",
                )
            )
        if record.prev_hash != expected_prev_hash:
            failures.append(
                AuditFailure(
                    seq=record.seq,
                    record_id=record.id,
                    reason=(
                        f"previous hash mismatch: expected {expected_prev_hash}, "
                        f"found {record.prev_hash}"
                    ),
                )
            )
        if record.detail_json == {}:
            if _HASH_PATTERN.fullmatch(record.hash) is None:
                failures.append(
                    AuditFailure(
                        seq=record.seq,
                        record_id=record.id,
                        reason="purged record has a malformed stored hash",
                    )
                )
        elif _record_hash(record, record.prev_hash) != record.hash:
            failures.append(
                AuditFailure(
                    seq=record.seq,
                    record_id=record.id,
                    reason="hash mismatch: stored hash does not match the canonical record",
                )
            )
        expected_seq = record.seq + 1
        expected_prev_hash = record.hash
    return VerifyResult(ok=not failures, checked=len(records), failures=tuple(failures))
