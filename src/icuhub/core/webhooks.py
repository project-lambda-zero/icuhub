"""Webhook ingress: verify before parse, dedupe durably, dispatch through the sync commit path."""

from __future__ import annotations

import hashlib
import secrets as pysecrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.core.audit import append as audit_append
from icuhub.core.credentials import EncryptedBlob
from icuhub.core.queue import DuplicateActiveJob, enqueue
from icuhub.core.services import get_services
from icuhub.kit.errors import WebhookRejected
from icuhub.kit.types import WebhookDelivery
from icuhub.storage.db import session_scope
from icuhub.storage.models import Connection, RawBatch, WebhookEndpoint
from icuhub.storage.models import Target as TargetRow
from icuhub.storage.models import WebhookDelivery as DeliveryRow
from icuhub.storage.system import lookup_webhook_endpoint

__all__ = ["JOB_HANDLERS", "Receipt", "create_endpoint", "receive", "rotate_endpoint", "run_webhook_job"]


@dataclass(frozen=True)
class Receipt:
    status_code: int
    delivery_id: str | None = None
    detail: str = ""


def _now() -> datetime:
    return datetime.now(UTC)


async def create_endpoint(
    session: AsyncSession, caller: Any, connection_id: uuid.UUID, secret: str | None = None
) -> tuple[str, str]:
    """Create a random ingress endpoint; the plaintext secret is returned only here."""
    services = get_services()
    connection = await session.get(Connection, connection_id)
    if connection is None or connection.tenant_id != caller.tenant_id:
        raise WebhookRejected("connection not found")
    plaintext = secret or pysecrets.token_urlsafe(32)
    ref = await services.broker.store(caller.tenant_id, f"webhook.{connection.slug}", plaintext.encode(), session=session)
    endpoint = WebhookEndpoint(
        id=pysecrets.token_urlsafe(32),
        tenant_id=caller.tenant_id,
        connection_id=connection_id,
        secret_ref=ref.ref,
    )
    session.add(endpoint)
    await session.flush()
    return endpoint.id, plaintext


async def rotate_endpoint(
    session: AsyncSession, caller: Any, endpoint_id: str, secret: str | None = None
) -> str:
    """Rotate the endpoint secret; the previous one stays valid for the rotation window."""
    services = get_services()
    endpoint = await session.get(WebhookEndpoint, endpoint_id)
    if endpoint is None or endpoint.tenant_id != caller.tenant_id:
        raise WebhookRejected("endpoint not found")
    plaintext = secret or pysecrets.token_urlsafe(32)
    ref = await services.broker.store(caller.tenant_id, f"webhook.{endpoint_id}", plaintext.encode(), session=session)
    endpoint.previous_secret_ref = endpoint.secret_ref
    endpoint.previous_valid_until = _now() + timedelta(seconds=services.settings.webhook_rotation_window_s)
    endpoint.secret_ref = ref.ref
    return plaintext


def _fallback_delivery_id(body: bytes, event_type: str | None) -> str:
    return "sha256:" + hashlib.sha256((event_type or "").encode() + b"\x00" + body).hexdigest()


async def receive(endpoint_id: str, headers: dict[str, str], body: bytes) -> Receipt:
    """Verify, dedupe, store, and enqueue one delivery. Never parses before verification."""
    services = get_services()
    endpoint = await lookup_webhook_endpoint(endpoint_id)
    if endpoint is None or endpoint.disabled_at is not None:
        return Receipt(status_code=404, detail="unknown endpoint")
    async with session_scope(endpoint.tenant_id) as session:
        connector = await services.runtime.open(session, endpoint.tenant_id, endpoint.connection_id)
        now = _now()
        secrets: list[bytes] = [await services.broker.resolve(endpoint.tenant_id, _ref(endpoint.secret_ref), session=session)]
        if endpoint.previous_secret_ref and endpoint.previous_valid_until and endpoint.previous_valid_until > now:
            secrets.append(await services.broker.resolve(endpoint.tenant_id, _ref(endpoint.previous_secret_ref), session=session))
        delivery = WebhookDelivery(headers=headers, body=body, received_at=now)
        verified = None
        last_error: WebhookRejected | None = None
        for secret in secrets:
            verifier = connector.webhook_verifier(secret)
            if verifier is None:
                return Receipt(status_code=405, detail="connector does not accept webhooks")
            try:
                verified = verifier.verify(delivery, now=now)
                break
            except WebhookRejected as exc:
                last_error = exc
        if verified is None:
            await audit_append(
                session,
                endpoint.tenant_id,
                ts=now,
                caller_id="webhook",
                connection_id=endpoint.connection_id,
                operation="webhook.verify",
                status="rejected",
                detail_json={"reason": type(last_error).__name__ if last_error else "unknown"},
            )
            return Receipt(status_code=401, detail="verification failed")
        vendor_id = verified.delivery_id or _fallback_delivery_id(body, verified.event_type)

        existing = (
            await session.execute(
                select(DeliveryRow).where(
                    DeliveryRow.connection_id == endpoint.connection_id,
                    DeliveryRow.vendor_delivery_id == vendor_id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return Receipt(status_code=200, delivery_id=str(existing.id), detail="duplicate")
        from icuhub.core.sync import _store_raw  # noqa: PLC0415

        raw = await _store_raw(
            session,
            endpoint.tenant_id,
            await session.get(Connection, endpoint.connection_id),
            origin="webhook",
            stream=verified.event_type or "webhook",
            payload=body,
            record_count=1,
            parser_version="0",
            sync_run_id=None,
        )
        row = DeliveryRow(
            tenant_id=endpoint.tenant_id,
            connection_id=endpoint.connection_id,
            endpoint_id=endpoint_id,
            vendor_delivery_id=vendor_id,
            event_type=verified.event_type,
            raw_batch_id=raw.id,
        )
        session.add(row)
        try:
            await session.flush()
        except IntegrityError:
            await session.rollback()
            return Receipt(status_code=200, delivery_id=vendor_id, detail="duplicate")
        await enqueue(
            session,
            "webhooks",
            "webhook",
            {
                "delivery_id": str(row.id),
                "tenant_id": str(endpoint.tenant_id),
                "headers": {
                    k: v
                    for k, v in headers.items()
                    if k.lower() not in {"authorization", "cookie", "x-api-key", "proxy-authorization"}
                },
            },
            tenant_id=endpoint.tenant_id,
            dedupe_key=f"{endpoint.tenant_id}:webhook:{row.id}",
        )
        return Receipt(status_code=202, delivery_id=str(row.id))


def _ref(value: str) -> Any:
    from icuhub.kit.types import SecretRef  # noqa: PLC0415

    return SecretRef(ref=value)


async def run_webhook_job(payload: dict[str, Any], lease: Any = None) -> dict[str, Any]:
    """Worker handler for the ``webhook`` job kind."""
    services = get_services()
    tenant_id = uuid.UUID(payload["tenant_id"])
    async with session_scope(tenant_id) as session:
        row = await session.get(DeliveryRow, uuid.UUID(payload["delivery_id"]))
        if row is None or row.status == "processed":
            return {"skipped": True}
        raw = await session.get(RawBatch, row.raw_batch_id)
        if raw is None:
            row.status = "failed"
            row.error = "RawBatchMissing"
            return {"status": "failed"}
        data = await services.broker.decrypt_blob(
            tenant_id,
            raw.id,
            EncryptedBlob(kek_id=raw.kek_id, dek_wrapped=raw.dek_wrapped, nonce=raw.nonce, ciphertext=raw.payload_enc),
        )
        connection = await session.get(Connection, row.connection_id)
        connector = await services.runtime.open(session, tenant_id, connection.id)
        delivery = WebhookDelivery(headers=payload.get("headers", {}), body=data, received_at=row.received_at)
        specs = [
            spec
            for spec in connector.webhooks().values()
            if row.event_type in spec.event_types or "*" in spec.event_types
        ]
        if not specs:
            row.status = "ignored"
            row.processed_at = _now()
            return {"status": "ignored"}
        from icuhub.core.auth_types import Caller  # noqa: PLC0415
        from icuhub.core.sync import commit_batch, trigger_sync  # noqa: PLC0415

        try:
            grouped: dict[str, list[dict[str, Any]]] = {}
            reconciliations = 0
            for spec in specs:
                for record in spec.fn(connector, delivery):
                    if record.reconcile is not None:
                        target_id: uuid.UUID | None = None
                        if record.target_uid is not None:
                            target = (
                                await session.execute(
                                    select(TargetRow).where(
                                        TargetRow.connection_id == connection.id,
                                        TargetRow.source_uid == record.target_uid,
                                    )
                                )
                            ).scalar_one_or_none()
                            target_id = target.id if target is not None else None
                        try:
                            await trigger_sync(
                                session,
                                Caller(id="webhook-reconcile", tenant_id=tenant_id, roles=frozenset({"system"})),
                                connection.id,
                                record.stream,
                                target_id=target_id,
                                mode=record.reconcile,
                            )
                        except DuplicateActiveJob:
                            # A repeated delivery reuses the active sync; the delivery still processes.
                            pass
                        reconciliations += 1
                        continue
                    grouped.setdefault(record.stream, []).append(record.raw)
            totals = {"findings": 0, "records": 0, "quarantined": 0}
            for stream, records in grouped.items():
                result = await commit_batch(
                    session,
                    connection=connection,
                    connector=connector,
                    stream=stream,
                    records=records,
                    origin="webhook",
                )
                for key in totals:
                    totals[key] += result[key]
            row.status = "processed"
            row.processed_at = _now()
            return {"status": "processed", **totals, "reconciliations": reconciliations}
        except Exception as exc:  # noqa: BLE001 - failure class is recorded at this boundary
            row.status = "failed"
            row.error = type(exc).__name__
            return {"status": "failed", "error": type(exc).__name__}


JOB_HANDLERS = {"webhook": run_webhook_job}
