"""Outbox relay: publishes committed ``outbox_event`` rows to Kafka.

Delivery is at-least-once. A row is marked ``relayed_at`` only after the producer confirms the
broker ack, and the mark commits in the same transaction that holds the row lock. A crash between
ack and commit leaves the row pending; the next run republishes identical value bytes, key, and
headers, so consumers dedupe on the CloudEvents ``id``.

Batches stop at the first publish failure to keep per-key ordering. The failed row records
``attempts`` and ``last_error`` in the same batch transaction, so the failure metadata commits.
"""

from __future__ import annotations

import ssl
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from aiokafka import AIOKafkaProducer
from aiokafka.errors import KafkaError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from icuhub.kit.types import SecretRef
from icuhub.storage.db import admin_session
from icuhub_schemas.events import CloudEvent

__all__ = [
    "AioKafkaProducerAdapter",
    "EventProducer",
    "OutboxRelay",
    "ProducerError",
    "ProducerNotStartedError",
    "PublishError",
    "RelayBatchResult",
    "SecretResolver",
]

CLOUDEVENTS_CONTENT_TYPE = b"application/cloudevents+json; charset=utf-8"
MAX_LAST_ERROR_CHARS = 1000

SecurityProtocol = Literal["PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL"]


class ProducerError(Exception):
    """Base class for producer lifecycle and publish failures."""


class ProducerNotStartedError(ProducerError):
    """Raised when a producer is used before ``start()`` or after ``stop()``."""


class PublishError(ProducerError):
    """Raised when the broker does not acknowledge a message."""


class SecretResolver(Protocol):
    """Resolves an opaque ``SecretRef`` to secret bytes (the credential broker implements this)."""

    async def resolve(self, ref: SecretRef) -> bytes: ...


class EventProducer(Protocol):
    """Publishes one message and returns only after the broker acknowledges it."""

    async def send_and_wait(
        self,
        *,
        topic: str,
        key: bytes | None,
        value: bytes,
        headers: Sequence[tuple[str, bytes]],
    ) -> None:
        """Raise ``PublishError`` if the broker does not acknowledge the message."""
        ...


@dataclass(frozen=True, slots=True)
class RelayBatchResult:
    """Outcome of one ``OutboxRelay.relay_batch`` call.

    ``published`` counts rows acknowledged and marked in this batch. ``failed_event_id`` is the row
    whose publish failed; the batch stopped there and that row stays pending.
    """

    published: int
    failed_event_id: str | None


class AioKafkaProducerAdapter:
    """``EventProducer`` backed by ``aiokafka.AIOKafkaProducer``.

    Configured with ``acks="all"`` and idempotence enabled. SASL credentials are ``SecretRef``
    values resolved through ``secrets`` at ``start()`` and never logged or included in ``repr``.
    Use as ``await start()`` ... ``await stop()``; ``send_and_wait`` before ``start()`` raises
    ``ProducerNotStartedError``.
    """

    def __init__(
        self,
        *,
        bootstrap_servers: str,
        security_protocol: SecurityProtocol = "PLAINTEXT",
        sasl_mechanism: str | None = None,
        sasl_username: SecretRef | None = None,
        sasl_password: SecretRef | None = None,
        ssl_context: ssl.SSLContext | None = None,
        secrets: SecretResolver | None = None,
    ) -> None:
        sasl_fields = (sasl_mechanism, sasl_username, sasl_password, secrets)
        if security_protocol.startswith("SASL_") and any(field is None for field in sasl_fields):
            raise ValueError("SASL security protocols require sasl_mechanism, sasl_username, sasl_password, secrets")
        self._bootstrap_servers = bootstrap_servers
        self._security_protocol = security_protocol
        self._sasl_mechanism = sasl_mechanism
        self._sasl_username = sasl_username
        self._sasl_password = sasl_password
        self._ssl_context = ssl_context
        self._secrets = secrets
        self._producer: AIOKafkaProducer | None = None

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(bootstrap_servers={self._bootstrap_servers!r}, "
            f"security_protocol={self._security_protocol!r})"
        )

    async def start(self) -> None:
        """Resolve SASL secrets and start the underlying producer."""

        if self._producer is not None:
            raise ProducerError("producer already started")
        username: str | None = None
        password: str | None = None
        if self._sasl_username is not None and self._sasl_password is not None and self._secrets is not None:
            username = (await self._secrets.resolve(self._sasl_username)).decode("utf-8")
            password = (await self._secrets.resolve(self._sasl_password)).decode("utf-8")
        producer = AIOKafkaProducer(
            bootstrap_servers=self._bootstrap_servers,
            security_protocol=self._security_protocol,
            sasl_mechanism=self._sasl_mechanism or "PLAIN",
            sasl_plain_username=username,
            sasl_plain_password=password,
            ssl_context=self._ssl_context,
            acks="all",
            enable_idempotence=True,
        )
        try:
            await producer.start()
        except KafkaError as exc:
            raise ProducerError(f"failed to start Kafka producer: {type(exc).__name__}") from exc
        self._producer = producer

    async def stop(self) -> None:
        """Stop the underlying producer. Safe to call when not started."""

        producer, self._producer = self._producer, None
        if producer is None:
            return
        try:
            await producer.stop()
        except KafkaError as exc:
            raise ProducerError(f"failed to stop Kafka producer: {type(exc).__name__}") from exc

    async def send_and_wait(
        self,
        *,
        topic: str,
        key: bytes | None,
        value: bytes,
        headers: Sequence[tuple[str, bytes]],
    ) -> None:
        """Publish one message and return after the broker acknowledges it."""

        producer = self._producer
        if producer is None:
            raise ProducerNotStartedError("producer is not started")
        try:
            await producer.send_and_wait(topic, value=value, key=key, headers=list(headers))
        except KafkaError as exc:
            raise PublishError(f"broker did not acknowledge message: {type(exc).__name__}") from exc


class OutboxRelay:
    """Publishes pending outbox rows in ``created_at, id`` order.

    ``relay_batch`` runs in one admin transaction: it claims up to ``batch_size`` pending rows with
    ``FOR UPDATE SKIP LOCKED`` and publishes them in order. Each acknowledged row is marked
    ``relayed_at`` in that transaction. A publish failure records ``attempts`` and ``last_error`` and
    ends the batch. Any other exception rolls the whole batch back, leaving every row pending.
    """

    def __init__(self, *, engine: AsyncEngine, producer: EventProducer, batch_size: int = 100) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be at least 1")
        self._engine = engine
        self._producer = producer
        self._batch_size = batch_size

    async def relay_batch(self) -> RelayBatchResult:
        """Publish one batch of pending rows and return the outcome."""

        async with admin_session(engine=self._engine) as session:
            rows = (
                await session.execute(
                    text("SELECT id, event_id, topic, event_json FROM icuhub_outbox_claim(:limit)"),
                    {"limit": self._batch_size},
                )
            ).all()
            published = 0
            for row in rows:
                event = CloudEvent.model_validate(row.event_json)
                try:
                    await self._producer.send_and_wait(
                        topic=row.topic,
                        key=event.subject.encode("utf-8") if event.subject is not None else None,
                        value=event.to_json().encode("utf-8"),
                        headers=[("content-type", CLOUDEVENTS_CONTENT_TYPE)],
                    )
                except PublishError as exc:
                    await session.execute(
                        text("SELECT icuhub_outbox_fail(:id, :error)"),
                        {"id": row.id, "error": f"{type(exc).__name__}: {exc}"[:MAX_LAST_ERROR_CHARS]},
                    )
                    return RelayBatchResult(published=published, failed_event_id=row.event_id)
                await session.execute(text("SELECT icuhub_outbox_mark(:id)"), {"id": row.id})
                published += 1
            return RelayBatchResult(published=published, failed_event_id=None)
