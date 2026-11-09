"""Behaviour of the outbox relay and the aiokafka adapter lifecycle. No live Kafka is contacted."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from icuhub.core.outbox import add_event
from icuhub.core.relay import (
    CLOUDEVENTS_CONTENT_TYPE,
    AioKafkaProducerAdapter,
    OutboxRelay,
    ProducerNotStartedError,
    PublishError,
    RelayBatchResult,
)
from icuhub.kit.types import SecretRef
from icuhub.storage.db import admin_session, create_engine, session_scope
from icuhub.storage.models import OutboxEvent, Tenant
from icuhub_schemas.events import CloudEvent


class SimulatedCrash(RuntimeError):  # noqa: N818  # test double for a process death, name kept for readability
    """Stands in for a process death after the broker acknowledged a message."""


@dataclass(frozen=True, slots=True)
class Delivered:
    topic: str
    key: bytes | None
    value: bytes
    headers: list[tuple[str, bytes]]


@dataclass
class FakeProducer:
    """Records broker-accepted messages. Can reject (``fail_ids``) or crash after ack (``crash_ids``) once."""

    fail_ids: set[str] = field(default_factory=set)
    crash_ids: set[str] = field(default_factory=set)
    before_send: Callable[[str], Awaitable[None]] | None = None
    attempted: list[str] = field(default_factory=list)
    delivered: list[Delivered] = field(default_factory=list)

    async def send_and_wait(
        self,
        *,
        topic: str,
        key: bytes | None,
        value: bytes,
        headers: Sequence[tuple[str, bytes]],
    ) -> None:
        event_id = CloudEvent.model_validate_json(value).id
        self.attempted.append(event_id)
        if self.before_send is not None:
            await self.before_send(event_id)
        if event_id in self.fail_ids:
            raise PublishError("broker rejected message")
        self.delivered.append(Delivered(topic=topic, key=key, value=value, headers=list(headers)))
        if event_id in self.crash_ids:
            self.crash_ids.discard(event_id)
            raise SimulatedCrash("process died after broker ack")


class _StaticSecrets:
    async def resolve(self, ref: SecretRef) -> bytes:
        return b"resolved"


@asynccontextmanager
async def _engine_pair(owner_url: str, app_url: str) -> AsyncGenerator[tuple[AsyncEngine, AsyncEngine]]:
    owner = create_engine(owner_url)
    app = create_engine(app_url)
    try:
        yield owner, app
    finally:
        await owner.dispose()
        await app.dispose()


def _event(index: int, subject: str | None) -> CloudEvent:
    return CloudEvent(
        id=f"caller-{index}",
        source="icuhub://connector/semgrep",
        type="icuhub.finding.upserted",
        time=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        subject=subject,
        data={"index": index},
    )


async def _seed(
    owner: AsyncEngine, app: AsyncEngine, tenant_id: uuid.UUID, events: list[CloudEvent], slug: str = "acme"
) -> list[str]:
    async with admin_session(engine=owner) as session:
        session.add(Tenant(id=tenant_id, slug=slug, display_name=slug.title()))
    event_ids: list[str] = []
    for event in events:
        async with session_scope(tenant_id, engine=app) as session:
            row = await add_event(session, tenant_id, event)
            event_ids.append(row.event_id)
    return event_ids


async def _rows(owner: AsyncEngine) -> list[dict[str, Any]]:
    async with admin_session(engine=owner) as session:
        result = await session.execute(
            select(
                OutboxEvent.event_id,
                OutboxEvent.topic,
                OutboxEvent.event_json,
                OutboxEvent.relayed_at,
                OutboxEvent.attempts,
                OutboxEvent.last_error,
            ).order_by(OutboxEvent.created_at, OutboxEvent.id)
        )
        return [dict(row) for row in result.mappings().all()]


async def _relayed_at(owner: AsyncEngine, event_id: str) -> datetime | None:
    async with admin_session(engine=owner) as session:
        return await session.scalar(select(OutboxEvent.relayed_at).where(OutboxEvent.event_id == event_id))


@pytest.mark.usefixtures("clean_database")
def test_publishes_pending_rows_in_order_with_cloudevents_structured_payload(
    owner_database_url: str, app_database_url: str
) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        async with _engine_pair(owner_database_url, app_database_url) as (owner, app):
            event_ids = await _seed(
                owner,
                app,
                tenant_id,
                [_event(1, "findings/f-1"), _event(2, None), _event(3, "findings/f-3")],
            )
            producer = FakeProducer()

            result = await OutboxRelay(engine=owner, producer=producer).relay_batch()
            rows = await _rows(owner)

        assert result == RelayBatchResult(published=3, failed_event_id=None)
        assert producer.attempted == event_ids
        assert [message.key for message in producer.delivered] == [b"findings/f-1", None, b"findings/f-3"]
        for message, row in zip(producer.delivered, rows, strict=True):
            assert message.topic == row["topic"] == "icuhub.acme.finding.upserted"
            assert message.headers == [("content-type", CLOUDEVENTS_CONTENT_TYPE)]
            assert message.value == CloudEvent.model_validate(row["event_json"]).to_json().encode("utf-8")
            assert CloudEvent.model_validate_json(message.value).id == row["event_id"]
        assert all(row["relayed_at"] is not None for row in rows)

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_row_is_not_marked_before_broker_ack(owner_database_url: str, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        async with _engine_pair(owner_database_url, app_database_url) as (owner, app):
            (event_id,) = await _seed(owner, app, tenant_id, [_event(1, "findings/f-1")])
            observed_before_ack: list[datetime | None] = []

            async def observe(_: str) -> None:
                observed_before_ack.append(await _relayed_at(owner, event_id))

            producer = FakeProducer(before_send=observe)
            await OutboxRelay(engine=owner, producer=producer).relay_batch()
            after = await _relayed_at(owner, event_id)

        assert observed_before_ack == [None]
        assert after is not None

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_publish_failure_stops_batch_and_records_attempt(owner_database_url: str, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        async with _engine_pair(owner_database_url, app_database_url) as (owner, app):
            event_ids = await _seed(
                owner,
                app,
                tenant_id,
                [_event(1, "findings/f-1"), _event(2, "findings/f-2"), _event(3, "findings/f-3")],
            )
            producer = FakeProducer(fail_ids={event_ids[1]})

            result = await OutboxRelay(engine=owner, producer=producer).relay_batch()
            rows = await _rows(owner)

        assert result == RelayBatchResult(published=1, failed_event_id=event_ids[1])
        assert producer.attempted == [event_ids[0], event_ids[1]]
        assert [row["relayed_at"] is not None for row in rows] == [True, False, False]
        failed, untouched = rows[1], rows[2]
        assert failed["attempts"] == 1
        assert failed["last_error"] is not None
        assert failed["last_error"].startswith("PublishError: ")
        assert untouched["attempts"] == 0
        assert untouched["last_error"] is None

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_app_role_relays_rows_across_tenants(owner_database_url: str, app_database_url: str) -> None:
    async def scenario() -> None:
        first_tenant, second_tenant = uuid.uuid4(), uuid.uuid4()
        async with _engine_pair(owner_database_url, app_database_url) as (owner, app):
            first_ids = await _seed(owner, app, first_tenant, [_event(1, "findings/a-1")])
            second_ids = await _seed(owner, app, second_tenant, [_event(2, "findings/b-1")], slug="globex")
            producer = FakeProducer(fail_ids={second_ids[0]})

            result = await OutboxRelay(engine=app, producer=producer).relay_batch()
            rows = await _rows(owner)

        assert result == RelayBatchResult(published=1, failed_event_id=second_ids[0])
        assert producer.attempted == [first_ids[0], second_ids[0]]
        assert [row["relayed_at"] is not None for row in rows] == [True, False]
        assert rows[1]["attempts"] == 1
        assert rows[1]["last_error"] is not None

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_crash_after_ack_rolls_back_and_replays_identically(owner_database_url: str, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        async with _engine_pair(owner_database_url, app_database_url) as (owner, app):
            event_ids = await _seed(owner, app, tenant_id, [_event(1, "findings/f-1"), _event(2, "findings/f-2")])
            producer = FakeProducer(crash_ids={event_ids[1]})
            relay = OutboxRelay(engine=owner, producer=producer)

            with pytest.raises(SimulatedCrash):
                await relay.relay_batch()
            rows_after_crash = await _rows(owner)

            result = await relay.relay_batch()
            rows_after_replay = await _rows(owner)

        assert [row["relayed_at"] for row in rows_after_crash] == [None, None]
        assert [row["attempts"] for row in rows_after_crash] == [0, 0]
        assert result == RelayBatchResult(published=2, failed_event_id=None)
        assert [message.value for message in producer.delivered[:2]] == [
            message.value for message in producer.delivered[2:]
        ]
        assert [message.key for message in producer.delivered[:2]] == [
            message.key for message in producer.delivered[2:]
        ]
        assert [message.headers for message in producer.delivered[:2]] == [
            message.headers for message in producer.delivered[2:]
        ]
        assert [row["event_id"] for row in rows_after_replay] == event_ids
        assert all(row["relayed_at"] is not None for row in rows_after_replay)

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_batch_size_bounds_each_run(owner_database_url: str, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        async with _engine_pair(owner_database_url, app_database_url) as (owner, app):
            event_ids = await _seed(owner, app, tenant_id, [_event(i, f"findings/f-{i}") for i in range(5)])
            producer = FakeProducer()
            relay = OutboxRelay(engine=owner, producer=producer, batch_size=2)

            results = [await relay.relay_batch() for _ in range(4)]

        assert results == [
            RelayBatchResult(published=2, failed_event_id=None),
            RelayBatchResult(published=2, failed_event_id=None),
            RelayBatchResult(published=1, failed_event_id=None),
            RelayBatchResult(published=0, failed_event_id=None),
        ]
        assert producer.attempted == event_ids

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_non_positive_batch_size_is_rejected(owner_database_url: str) -> None:
    async def scenario() -> None:
        owner = create_engine(owner_database_url)
        try:
            with pytest.raises(ValueError, match="batch_size"):
                OutboxRelay(engine=owner, producer=FakeProducer(), batch_size=0)
        finally:
            await owner.dispose()

    asyncio.run(scenario())


def test_send_before_start_is_rejected() -> None:
    adapter = AioKafkaProducerAdapter(bootstrap_servers="kafka:9092")

    async def scenario() -> None:
        await adapter.send_and_wait(topic="icuhub.acme.finding.upserted", key=None, value=b"{}", headers=[])

    with pytest.raises(ProducerNotStartedError):
        asyncio.run(scenario())


def test_stop_without_start_is_a_no_op() -> None:
    adapter = AioKafkaProducerAdapter(bootstrap_servers="kafka:9092")
    asyncio.run(adapter.stop())


def test_repr_excludes_secret_references() -> None:
    adapter = AioKafkaProducerAdapter(
        bootstrap_servers="kafka:9092",
        security_protocol="SASL_SSL",
        sasl_mechanism="PLAIN",
        sasl_username=SecretRef(ref="kafka-user-marker"),
        sasl_password=SecretRef(ref="kafka-pass-marker"),
        secrets=_StaticSecrets(),
    )

    rendered = repr(adapter)

    assert "kafka:9092" in rendered
    assert "SASL_SSL" in rendered
    assert "marker" not in rendered


def test_sasl_protocol_requires_credentials_and_resolver() -> None:
    with pytest.raises(ValueError, match="SASL"):
        AioKafkaProducerAdapter(
            bootstrap_servers="kafka:9092",
            security_protocol="SASL_SSL",
            sasl_mechanism="PLAIN",
            sasl_username=SecretRef(ref="kafka-user"),
            sasl_password=SecretRef(ref="kafka-pass"),
            secrets=None,
        )
