"""Transactional outbox insertion for CloudEvents.

``add_event`` writes an event into ``outbox_event`` inside the caller's transaction, so the event
commits or rolls back together with the state change that produced it. The relay publishes rows
after they commit (see ``icuhub.core.relay``).

The outbox event ID is derived from stable event content, so retrying the same logical event
converges on one row. Consumers dedupe on the CloudEvents ``id``, which equals the outbox
``event_id``.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.storage.models import OutboxEvent, Tenant
from icuhub_schemas.events import EVENT_TYPE_PREFIX, CloudEvent

__all__ = ["TOPIC_PREFIX", "UnknownTenantError", "add_event", "outbox_event_id", "topic_for"]

TOPIC_PREFIX = "icuhub"


class UnknownTenantError(LookupError):
    """Raised when an event is added for a tenant that does not exist."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def outbox_event_id(tenant_id: uuid.UUID, event: CloudEvent) -> str:
    """Return the deterministic outbox event ID (hex SHA-256) for ``event`` emitted for ``tenant_id``.

    The identity is ``tenant_id``, ``source``, ``subject``, ``type``, and a revision digest of the
    canonical JSON of ``data``. A change in any of these yields a new ID. ``time``, the caller's
    ``id``, and the extension attributes are excluded, so a retry that regenerates them keeps the ID.
    """

    data = event.model_dump(mode="json")["data"]
    revision = hashlib.sha256(_canonical_json(data).encode("utf-8")).hexdigest()
    identity = {
        "tenant_id": str(tenant_id),
        "source": event.source,
        "subject": event.subject,
        "type": event.type,
        "revision": revision,
    }
    return hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()


def topic_for(tenant_slug: str, event_type: str, *, topic_prefix: str = TOPIC_PREFIX) -> str:
    """Return the Kafka topic ``<topic_prefix>.<tenant_slug>.<type without the icuhub. prefix>``."""

    return f"{topic_prefix}.{tenant_slug}.{event_type.removeprefix(EVENT_TYPE_PREFIX)}"


async def add_event(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    event: CloudEvent,
    *,
    topic_prefix: str = TOPIC_PREFIX,
) -> OutboxEvent:
    """Insert ``event`` into the outbox within the caller's transaction and return the outbox row.

    The stored CloudEvent carries ``id`` equal to the derived outbox ``event_id``; any ``id`` the
    caller supplied is replaced. Inserting an event whose ID already exists is a no-op, and the
    existing row is returned. The caller owns commit and rollback. ``topic_prefix`` is the
    configured Kafka topic prefix (composition root passes the settings value).

    Raises ``UnknownTenantError`` when ``tenant_id`` has no ``tenant`` row.
    """

    slug = await session.scalar(select(Tenant.slug).where(Tenant.id == tenant_id))
    if slug is None:
        raise UnknownTenantError(f"tenant {tenant_id} does not exist")

    event_id = outbox_event_id(tenant_id, event)
    stored = event.model_copy(update={"id": event_id})
    await session.execute(
        pg_insert(OutboxEvent)
        .values(
            tenant_id=tenant_id,
            event_id=event_id,
            topic=topic_for(slug, event.type, topic_prefix=topic_prefix),
            event_json=stored.model_dump(mode="json", exclude_none=True),
        )
        .on_conflict_do_nothing(index_elements=[OutboxEvent.event_id])
    )
    row = await session.scalar(select(OutboxEvent).where(OutboxEvent.event_id == event_id))
    if row is None:
        raise RuntimeError(f"outbox row {event_id} missing after insert")
    return row
