"""Archer read operations: thin typed mappings over ArcherClient."""

import base64
import hashlib
from typing import Any

from .models import (
    ApplicationRef,
    ArcherContent,
    ArcherItem,
    AttachmentOutput,
    AttachmentRef,
    ContentOutput,
    ContentRef,
    DataFeedHistoryOutput,
    DiscoverOutput,
    EmptyInput,
    HistoryOutput,
    ItemsOutput,
    LevelRef,
    SearchContentArgs,
    SearchContentOutput,
    ValuesListRef,
    VersionOutput,
)

__all__ = [
    "discover_content_api",
    "get_attachment",
    "get_content",
    "get_data_feed_history",
    "get_history",
    "get_record_soap",
    "get_version",
    "list_applications",
    "list_fields",
    "list_levels",
    "list_values",
    "search_content",
]


def _items(objects: list[dict[str, Any]]) -> ItemsOutput:
    items = []
    for obj in objects:
        obj_id = obj.get("Id")
        if obj_id is None:
            continue
        items.append(ArcherItem(id=int(obj_id), name=obj.get("Name"), raw=obj))
    return ItemsOutput(items=items)


async def get_version(connector, args: EmptyInput) -> VersionOutput:
    return await connector.api.version()


async def list_applications(connector, args: EmptyInput) -> ItemsOutput:
    return _items(await connector.api.applications())


async def list_levels(connector, args: ApplicationRef) -> ItemsOutput:
    return _items(await connector.api.levels(args.application_id))


async def list_fields(connector, args: LevelRef) -> ItemsOutput:
    return _items(await connector.api.fields_for_level(args.level_id))


async def list_values(connector, args: ValuesListRef) -> ItemsOutput:
    tree = await connector.api.values_list(args.values_list_id)
    items: list[ArcherItem] = []

    def walk(nodes: Any, depth: int) -> None:
        for node in nodes or []:
            data = node.get("Data") or {}
            node_id = data.get("Id")
            if node_id is None:
                continue
            raw = dict(data)
            raw["depth"] = int(node.get("Depth", depth))
            items.append(ArcherItem(id=int(node_id), name=data.get("Name"), raw=raw))
            walk(node.get("Children"), depth + 1)

    walk(tree.get("Children"), 0)
    return ItemsOutput(items=items)


async def discover_content_api(connector, args: EmptyInput) -> DiscoverOutput:
    available, status = await connector.api.content_api()
    return DiscoverOutput(available=available, status=status)


async def search_content(connector, args: SearchContentArgs) -> SearchContentOutput:
    application_id = None
    for mapping in connector.config.record_types.values():
        if mapping.level_id == args.level_id:
            application_id = mapping.application_id
            break
    fields = await connector.api.fields_for_level(args.level_id)
    display = {str(f["Name"]): int(f["Id"]) for f in fields if f.get("Id") is not None and f.get("Name")}
    records = await connector.api.search_records(
        level_id=args.level_id,
        application_id=application_id,
        page_number=args.page_number,
        page_size=args.page_size,
        display_fields=display or None,
    )
    items = [
        ArcherItem(id=int(r["content_id"]), name=None, raw=r)
        for r in records
    ]
    return SearchContentOutput(
        records=items,
        page_number=args.page_number,
        has_more=len(records) == args.page_size,
    )


def _content_output(content_id: int, obj: dict[str, Any]) -> ContentOutput:
    field_contents = obj.get("FieldContents") or {}
    fields: dict[str, Any] = {}
    for fid, entry in field_contents.items():
        if isinstance(entry, dict):
            fields[str(fid)] = entry.get("Value", entry.get("IpAddressBytes"))
        else:
            fields[str(fid)] = entry
    content = ArcherContent(
        content_id=int(obj.get("Id", content_id)),
        level_id=obj.get("LevelId"),
        version=obj.get("Version"),
        fields=fields,
        raw=obj,
    )
    return ContentOutput(content=content)


async def get_content(connector, args: ContentRef) -> ContentOutput:
    return _content_output(args.content_id, await connector.api.content(args.content_id))


async def get_record_soap(connector, args: ContentRef) -> ContentOutput:
    record = await connector.api.record_soap(args.content_id)
    content = ArcherContent(
        content_id=int(record["content_id"]),
        level_id=None,
        version=None,
        fields=dict(record.get("fields") or {}),
        raw=record,
    )
    return ContentOutput(content=content)


async def get_history(connector, args: ContentRef) -> HistoryOutput:
    return HistoryOutput(entries=await connector.api.history(args.content_id))


async def get_attachment(connector, args: AttachmentRef) -> AttachmentOutput:
    data = await connector.api.attachment_bytes(args.attachment_id)
    return AttachmentOutput(
        attachment_id=args.attachment_id,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        content_base64=base64.b64encode(data).decode("ascii"),
    )


async def get_data_feed_history(connector, args: EmptyInput) -> DataFeedHistoryOutput:
    return DataFeedHistoryOutput(runs=await connector.api.data_feed_history())
