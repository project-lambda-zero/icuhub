"""Decorator registry: collection, inheritance merge, and class-creation validation."""

from __future__ import annotations

from typing import ClassVar, cast

import pytest
from pydantic import BaseModel

from icuhub.kit.connector import Connector, action, importer, mapper, operation, stream, webhook
from icuhub.kit.cursors import TimeIdCursor
from icuhub.kit.types import RawBatch


class GetArgs(BaseModel):
    key: str


class GetOut(BaseModel):
    key: str


class TransitionArgs(BaseModel):
    key: str
    to_status: str


class _Base(Connector):
    kind: ClassVar[str] = "base_tracker"
    version: ClassVar[str] = "1"
    display_name: ClassVar[str] = "Base Tracker"
    capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)
    flows: ClassVar[tuple[str, ...]] = ("F-TEST-1",)

    @stream("items", cursor=TimeIdCursor, capability="Tracker")
    async def items(self, target, checkpoint, mode):
        yield RawBatch(records=[], checkpoint=None, complete=True)


class _Full(Connector):
    kind: ClassVar[str] = "full_tracker"
    version: ClassVar[str] = "1"
    display_name: ClassVar[str] = "Full Tracker"
    capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)
    flows: ClassVar[tuple[str, ...]] = ("F-TEST-1",)

    @stream("items", cursor=TimeIdCursor, capability="Tracker", ocsf_class=2001, record_type="ticket")
    async def items(self, target, checkpoint, mode):
        yield RawBatch(records=[], checkpoint=None, complete=True)

    @mapper("items", version=2)
    def map_item(self, raw, ctx):
        return []

    @operation("get", input_model=GetArgs, output_model=GetOut, capability="Tracker")
    async def get(self, args):
        return GetOut(key=args.key)

    @action(
        "transition",
        classification="write",
        capability="Tracker",
        input_model=TransitionArgs,
        idempotency="key",
    )
    async def plan_transition(self, args):
        raise NotImplementedError

    @plan_transition.apply
    async def apply_transition(self, plan):
        raise NotImplementedError

    @webhook(event_types=("issue.created",), header_event="x-event")
    def parse_delivery(self, delivery):
        return []

    @importer("fpr", stream="items", media_types=("application/xml",), extensions=(".fvdl",))
    async def parse_fpr(self, file):
        yield {}


def test_each_declaration_kind_is_collected_with_its_metadata() -> None:
    streams = _Full.streams()
    assert set(streams) == {"items"}
    assert streams["items"].capability == "Tracker"
    assert streams["items"].ocsf_class == 2001
    assert streams["items"].record_type == "ticket"
    assert streams["items"].modes == ("incremental", "full")

    mappers = _Full.mappers()
    assert mappers["items"].version == 2

    assert set(_Full.operations()) == {"get"}
    assert _Full.operations()["get"].input_model is GetArgs

    actions = _Full.actions()
    assert set(actions) == {"transition"}
    assert actions["transition"].apply is not None
    assert actions["transition"].idempotency == "key"

    # Webhooks are keyed by the decorated attribute name, not by an event name.
    assert set(_Full.webhooks()) == {"parse_delivery"}
    assert _Full.webhooks()["parse_delivery"].event_types == ("issue.created",)

    assert set(_Full.importers()) == {"fpr"}
    assert _Full.importers()["fpr"].stream == "items"


def test_subclass_inherits_base_streams_and_adds_its_own_mapper() -> None:
    class Child(_Base):
        kind: ClassVar[str] = "child_tracker"
        version: ClassVar[str] = "1"
        display_name: ClassVar[str] = "Child Tracker"

        @mapper("items", version=1)
        def map_item(self, raw, ctx):
            return []

    assert set(Child.streams()) == {"items"}
    assert set(Child.mappers()) == {"items"}
    # The base class registry is not mutated by the subclass.
    assert _Base.mappers() == {}


def test_mapper_for_undeclared_stream_is_rejected() -> None:
    with pytest.raises(TypeError, match="mapper references undeclared stream 'missing'"):

        class Bad(Connector):
            kind: ClassVar[str] = "bad"
            capabilities: ClassVar[tuple[str, ...]] = ()

            @mapper("missing", version=1)
            def map_item(self, raw, ctx):
                return []


def test_mapper_must_be_sync() -> None:
    with pytest.raises(TypeError, match="must be a sync function"):

        class Bad(_Base):
            kind: ClassVar[str] = "bad_async_mapper"

            @mapper("items", version=1)
            async def map_item(self, raw, ctx):
                return []


def test_mapper_version_must_be_positive() -> None:
    with pytest.raises(TypeError, match="version must be >= 1"):

        class Bad(_Base):
            kind: ClassVar[str] = "bad_version"

            @mapper("items", version=0)
            def map_item(self, raw, ctx):
                return []


def test_unknown_capability_is_rejected() -> None:
    with pytest.raises(TypeError, match="unknown capability 'Bogus'"):

        class Bad(Connector):
            kind: ClassVar[str] = "bad_capability"
            capabilities: ClassVar[tuple[str, ...]] = ("Bogus",)

            @stream("items", cursor=TimeIdCursor, capability="Bogus")
            async def items(self, target, checkpoint, mode):
                yield RawBatch(records=[], checkpoint=None, complete=True)


def test_capability_must_be_declared_on_the_class() -> None:
    with pytest.raises(TypeError, match="not declared in capabilities"):

        class Bad(Connector):
            kind: ClassVar[str] = "undeclared_capability"
            capabilities: ClassVar[tuple[str, ...]] = ()

            @stream("items", cursor=TimeIdCursor, capability="Tracker")
            async def items(self, target, checkpoint, mode):
                yield RawBatch(records=[], checkpoint=None, complete=True)


def test_stream_must_be_an_async_generator() -> None:
    with pytest.raises(TypeError, match="must be an async generator function"):

        class Bad(Connector):
            kind: ClassVar[str] = "sync_stream"
            capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)

            @stream("items", cursor=TimeIdCursor, capability="Tracker")
            def items(self, target, checkpoint, mode):
                return []


def test_stream_cursor_must_be_a_pydantic_model() -> None:
    with pytest.raises(TypeError, match="must use a pydantic BaseModel subclass"):

        class Bad(Connector):
            kind: ClassVar[str] = "bad_cursor"
            capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)

            @stream("items", cursor=cast(type[BaseModel], dict), capability="Tracker")
            async def items(self, target, checkpoint, mode):
                yield RawBatch(records=[], checkpoint=None, complete=True)


def test_stream_modes_must_be_a_subset_of_the_registered_modes() -> None:
    with pytest.raises(TypeError, match="modes must be a non-empty subset of incremental/full/event/replay/targeted"):

        class Bad(Connector):
            kind: ClassVar[str] = "bad_modes"
            capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)

            @stream("items", cursor=TimeIdCursor, capability="Tracker", modes=("snapshot",))
            async def items(self, target, checkpoint, mode):
                yield RawBatch(records=[], checkpoint=None, complete=True)


def test_stream_accepts_targeted_mode_alongside_full() -> None:
    class Targeted(Connector):
        kind: ClassVar[str] = "targeted_modes"
        capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)

        @stream("items", cursor=TimeIdCursor, capability="Tracker", modes=("full", "targeted"))
        async def items(self, target, checkpoint, mode):
            yield RawBatch(records=[], checkpoint=None, complete=True)

    assert Targeted.streams()["items"].modes == ("full", "targeted")


def test_duplicate_stream_name_is_rejected() -> None:
    with pytest.raises(TypeError, match="duplicate stream 'items'"):

        class Bad(Connector):
            kind: ClassVar[str] = "dup_stream"
            capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)

            @stream("items", cursor=TimeIdCursor, capability="Tracker")
            async def first(self, target, checkpoint, mode):
                yield RawBatch(records=[], checkpoint=None, complete=True)

            @stream("items", cursor=TimeIdCursor, capability="Tracker")
            async def second(self, target, checkpoint, mode):
                yield RawBatch(records=[], checkpoint=None, complete=True)


def test_operation_classification_must_be_read() -> None:
    with pytest.raises(TypeError, match="classification must be 'read'"):

        class Bad(Connector):
            kind: ClassVar[str] = "write_operation"
            capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)

            @operation(
                "delete_it",
                input_model=GetArgs,
                output_model=GetOut,
                classification="write",
                capability="Tracker",
            )
            async def delete_it(self, args):
                return GetOut(key=args.key)


def test_action_without_apply_is_rejected() -> None:
    with pytest.raises(TypeError, match="has no @transition.apply function"):

        class Bad(Connector):
            kind: ClassVar[str] = "action_without_apply"
            capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)

            @action(
                "transition",
                classification="write",
                capability="Tracker",
                input_model=TransitionArgs,
                idempotency="key",
            )
            async def plan_transition(self, args):
                raise NotImplementedError


def test_duplicate_action_name_is_rejected() -> None:
    with pytest.raises(TypeError, match="duplicate action name 'transition'"):

        class Bad(Connector):
            kind: ClassVar[str] = "dup_action"
            capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)

            @action(
                "transition",
                classification="write",
                capability="Tracker",
                input_model=TransitionArgs,
                idempotency="key",
            )
            async def plan_first(self, args):
                raise NotImplementedError

            @plan_first.apply
            async def apply_first(self, plan):
                raise NotImplementedError

            @action(
                "transition",
                classification="write",
                capability="Tracker",
                input_model=TransitionArgs,
                idempotency="key",
            )
            async def plan_second(self, args):
                raise NotImplementedError

            @plan_second.apply
            async def apply_second(self, plan):
                raise NotImplementedError


def test_webhook_without_event_types_is_rejected() -> None:
    with pytest.raises(TypeError, match="declares no event_types"):

        class Bad(Connector):
            kind: ClassVar[str] = "webhook_no_events"

            @webhook(event_types=())
            def parse_delivery(self, delivery):
                return []


def test_webhook_must_be_sync() -> None:
    with pytest.raises(TypeError, match="must be a sync function"):

        class Bad(Connector):
            kind: ClassVar[str] = "async_webhook"

            @webhook(event_types=("issue.created",))
            async def parse_delivery(self, delivery):
                return []


def test_importer_must_declare_a_media_type_or_extension() -> None:
    with pytest.raises(TypeError, match="declares neither media_types nor extensions"):

        class Bad(Connector):
            kind: ClassVar[str] = "bad_importer"
            capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)

            @stream("items", cursor=TimeIdCursor, capability="Tracker")
            async def items(self, target, checkpoint, mode):
                yield RawBatch(records=[], checkpoint=None, complete=True)

            @importer("fpr", stream="items", media_types=(), extensions=())
            async def parse_fpr(self, file):
                yield {}


def test_importer_must_reference_a_declared_stream() -> None:
    with pytest.raises(TypeError, match="references undeclared stream 'items'"):

        class Bad(Connector):
            kind: ClassVar[str] = "importer_no_stream"

            @importer("fpr", stream="items", media_types=("application/xml",), extensions=())
            async def parse_fpr(self, file):
                yield {}
