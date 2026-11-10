"""Deterministic plan, apply, and reconcile workflows for Archer writes."""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any

from icuhub.kit import (
    ActionOutcome,
    ActionPlan,
    BudgetExhausted,
    ConfigError,
    Conflict,
    NotFound,
    OutcomeUnknown,
    PermissionDenied,
    StalePlan,
)

from .models import (
    ArcherRecordTypeMap,
    CreateFindingOrExceptionInput,
    DeleteContentInput,
    ExecuteDataFeedInput,
    UpdateFindingOrExceptionInput,
    UploadAttachmentInput,
)

__all__ = [
    "action_identity",
    "apply_create",
    "apply_delete",
    "apply_execute_data_feed",
    "apply_update",
    "apply_upload_attachment",
    "plan_create",
    "plan_delete",
    "plan_execute_data_feed",
    "plan_update",
    "plan_upload_attachment",
    "reconcile_create",
    "reconcile_delete",
    "reconcile_execute_data_feed",
    "reconcile_update",
    "reconcile_upload_attachment",
]


def action_identity(connector: Any, action: str, key: str) -> str:
    """Return a stable tenant-scoped action identity."""
    material = f"{connector.ctx.tenant_id}\x1f{action}\x1f{key}".encode()
    return hashlib.sha256(material).hexdigest()


def _mapping(connector: Any, record_type: str) -> ArcherRecordTypeMap:
    mapping = connector.config.record_types.get(record_type)
    if mapping is None:
        raise ConfigError(f"Archer record_types has no mapping for {record_type!r}")
    return mapping


def _require_write(connector: Any) -> None:
    if not connector.config.write_enabled:
        raise ConfigError("Archer writes are disabled by write_enabled=False")


def _require_destructive(connector: Any) -> None:
    if not connector.config.destructive_enabled:
        raise ConfigError("Archer delete is disabled by destructive_enabled=False")


def _check_version(current: dict[str, Any], expected_version: int) -> None:
    version = current.get("Version")
    if version is not None and int(version) != expected_version:
        raise StalePlan(f"Archer content Version {version} does not match expected {expected_version}")


async def _field_id(connector: Any, mapping: ArcherRecordTypeMap, field_name: str) -> int:
    configured = mapping.field_ids.get(field_name)
    if configured is not None:
        return int(configured)
    fields = await connector.api.fields_for_level(mapping.level_id)
    for field in fields:
        if field.get("Name") == field_name:
            return int(field["Id"])
    raise ConfigError(f"Archer level {mapping.level_id} has no field named {field_name!r}")


async def _correlation_search(
    connector: Any,
    mapping: ArcherRecordTypeMap,
    field_id: int,
    correlation_value: str,
) -> list[dict[str, Any]]:
    return await connector.api.search_records(
        level_id=mapping.level_id,
        application_id=mapping.application_id,
        page_number=1,
        page_size=1,
        display_fields={mapping.correlation_field or "Correlation": field_id},
        modified_since=None,
        time_field_id=None,
        text_filter=(field_id, correlation_value),
    )


def _stored_value(field: dict[str, Any] | None) -> Any:
    if not isinstance(field, dict):
        return None
    if "Value" in field:
        return field["Value"]
    return field.get("IpAddressBytes")


def _desired_value(field: dict[str, Any]) -> Any:
    if "Value" in field:
        return field["Value"]
    return field.get("IpAddressBytes")


def _field_contents(current: dict[str, Any]) -> dict[str, Any]:
    contents = current.get("FieldContents")
    return contents if isinstance(contents, dict) else {}


def _changed_fields(
    current: dict[str, Any], values: dict[str, Any], encoded: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    diff: dict[str, dict[str, Any]] = {}
    contents = _field_contents(current)
    for name, (field_id, desired_field) in zip(values, encoded.items(), strict=True):
        current_field = contents.get(str(field_id))
        desired = _desired_value(desired_field)
        if not isinstance(current_field, dict) or _stored_value(current_field) != desired:
            diff[name] = {"from": _stored_value(current_field), "to": desired}
    return diff


def _requested_values_present(
    current: dict[str, Any], encoded: dict[str, dict[str, Any]]
) -> bool:
    contents = _field_contents(current)
    for field_id, desired_field in encoded.items():
        current_field = contents.get(str(field_id))
        if not isinstance(current_field, dict):
            return False
        if _stored_value(current_field) != _desired_value(desired_field):
            return False
    return True


async def _read_back_fields(
    connector: Any, content_id: int, encoded: dict[str, dict[str, Any]]
) -> str | None:
    """Return None when the mapped fields read back as requested, else the reason they did not."""
    try:
        current = await connector.api.content(content_id)
    except (NotFound, OutcomeUnknown) as exc:
        return f"read-back failed: {type(exc).__name__}"
    if not _requested_values_present(current, encoded):
        return "read-back does not match the requested field values"
    return None


async def plan_create(connector: Any, args: CreateFindingOrExceptionInput) -> ActionPlan:
    mapping = _mapping(connector, args.record_type)
    field_values = dict(args.field_values)
    correlation_field_id: int | None = None
    existing: list[dict[str, Any]] = []
    if mapping.correlation_field:
        field_values[mapping.correlation_field] = args.correlation_value
        correlation_field_id = await _field_id(connector, mapping, mapping.correlation_field)
        existing = await _correlation_search(connector, mapping, correlation_field_id, args.correlation_value)
    preconditions = {
        "application_id": mapping.application_id,
        "level_id": mapping.level_id,
        "correlation_field": mapping.correlation_field,
        "correlation_field_id": correlation_field_id,
        "correlation_value": args.correlation_value,
    }
    request = {
        "level_id": mapping.level_id,
        "field_values": field_values,
        "record_type": args.record_type,
    }
    identity = action_identity(
        connector,
        "create_finding_or_exception",
        f"{mapping.level_id}:{args.correlation_value}",
    )
    if existing:
        content_id = int(existing[0]["content_id"])
        return ActionPlan(
            action="create_finding_or_exception",
            target_ref=str(content_id),
            diff={},
            preconditions=preconditions,
            idempotency_key=identity,
            changed=False,
            request=request,
        )
    return ActionPlan(
        action="create_finding_or_exception",
        target_ref=f"archer:{mapping.level_id}:{args.correlation_value}",
        diff={"create": dict(args.field_values)},
        preconditions=preconditions,
        idempotency_key=identity,
        changed=True,
        request=request,
    )


async def apply_create(connector: Any, plan: ActionPlan) -> ActionOutcome:
    if not plan.changed:
        return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
    _require_write(connector)
    try:
        encoded = await connector.api.encode_fields(
            int(plan.request["level_id"]), plan.request["field_values"]
        )
        content_id = await connector.api.create_content(int(plan.request["level_id"]), encoded)
    except OutcomeUnknown as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    reason = await _read_back_fields(connector, content_id, encoded)
    if reason is not None:
        return ActionOutcome(status="outcome_unknown", vendor_ref=str(content_id), error=reason)
    return ActionOutcome(
        status="succeeded", vendor_ref=str(content_id), result={"content_id": content_id}
    )


async def reconcile_create(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    field_name = plan.preconditions.get("correlation_field")
    field_id = plan.preconditions.get("correlation_field_id")
    if not field_name or field_id is None:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)
    mapping = _mapping(connector, str(plan.request["record_type"]))
    matches = await _correlation_search(
        connector,
        mapping,
        int(field_id),
        str(plan.preconditions["correlation_value"]),
    )
    if not matches:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)
    content_id = int(matches[0]["content_id"])
    return ActionOutcome(
        status="succeeded", vendor_ref=str(content_id), result={"content_id": content_id}
    )


async def plan_update(connector: Any, args: UpdateFindingOrExceptionInput) -> ActionPlan:
    mapping = _mapping(connector, args.record_type)
    current = await connector.api.content(args.content_id)
    _check_version(current, args.expected_version)
    encoded = await connector.api.encode_fields(mapping.level_id, args.field_values)
    diff = _changed_fields(current, args.field_values, encoded)
    return ActionPlan(
        action="update_finding_or_exception",
        target_ref=str(args.content_id),
        diff=diff,
        preconditions={"version": args.expected_version},
        idempotency_key=action_identity(
            connector,
            "update_finding_or_exception",
            f"{args.content_id}:{args.expected_version}:{args.field_values}",
        ),
        changed=bool(diff),
        request={
            "content_id": args.content_id,
            "level_id": mapping.level_id,
            "record_type": args.record_type,
            "field_values": dict(args.field_values),
        },
    )


async def apply_update(connector: Any, plan: ActionPlan) -> ActionOutcome:
    if not plan.changed:
        return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
    _require_write(connector)
    encoded = await connector.api.encode_fields(
        int(plan.request["level_id"]), plan.request["field_values"]
    )
    try:
        response = await connector.api.update_content(
            int(plan.request["content_id"]),
            int(plan.request["level_id"]),
            encoded,
            int(plan.preconditions["version"]),
        )
    except OutcomeUnknown as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    content_id = int(plan.request["content_id"])
    reason = await _read_back_fields(connector, content_id, encoded)
    if reason is not None:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=reason)
    return ActionOutcome(
        status="succeeded",
        vendor_ref=plan.target_ref,
        result={"content_id": content_id, "response": response},
    )


async def reconcile_update(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    current = await connector.api.content(int(plan.request["content_id"]))
    encoded = await connector.api.encode_fields(
        int(plan.request["level_id"]), plan.request["field_values"]
    )
    if _requested_values_present(current, encoded):
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
    return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)


def _field_attachments(current: dict[str, Any], field_id: int) -> list[dict[str, Any]]:
    field = _field_contents(current).get(str(field_id))
    if not isinstance(field, dict):
        return []
    value = field.get("Value")
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict) and item.get("Id") is not None]


async def _digest_matches(connector: Any, attachment_id: int, digest: str) -> bool:
    """Compare a stored attachment to ``digest``; unreadable or over-cap files cannot match."""
    try:
        payload = await connector.api.attachment_bytes(attachment_id)
    except (BudgetExhausted, NotFound):
        return False
    return hashlib.sha256(payload).hexdigest() == digest


async def _existing_attachment_with_digest(
    connector: Any, current: dict[str, Any], field_id: int, digest: str
) -> int | None:
    for item in _field_attachments(current, field_id):
        attachment_id = int(item["Id"])
        if await _digest_matches(connector, attachment_id, digest):
            return attachment_id
    return None


async def _associate_attachment(
    connector: Any, plan: ActionPlan, field_id: int, attachment_id: int
) -> None:
    """Attach ``attachment_id`` to the content, preserving every existing attachment ID.

    The write uses the content's current Version re-read here, because the upload itself
    may have advanced it.
    """
    content_id = int(plan.request["content_id"])
    mapping = _mapping(connector, str(plan.request["record_type"]))
    current = await connector.api.content(content_id)
    existing = _field_attachments(current, field_id)
    if any(int(item["Id"]) == attachment_id for item in existing):
        return
    items = [*existing, {"Id": attachment_id, "Name": str(plan.request["filename"])}]
    # [UNVERIFIED] Type 11 (attachment) FieldContents write shape. encode_fields has no
    # attachment branch, so the entry is built here; confirm against the Archer contract.
    await connector.api.update_content(
        content_id,
        mapping.level_id,
        {str(field_id): {"Type": 11, "Value": items, "FieldId": field_id}},
        int(current["Version"]),
    )


async def _verify_attachment(
    connector: Any, plan: ActionPlan, field_id: int, attachment_id: int
) -> ActionOutcome:
    content_id = int(plan.request["content_id"])
    try:
        current = await connector.api.content(content_id)
        if attachment_id not in {int(item["Id"]) for item in _field_attachments(current, field_id)}:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=str(attachment_id),
                error="attachment is not associated with the content after the write",
                result={"attachment_id": attachment_id},
            )
        payload = await connector.api.attachment_bytes(attachment_id)
    except (NotFound, OutcomeUnknown) as exc:
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=str(attachment_id),
            error=f"read-back failed: {type(exc).__name__}",
            result={"attachment_id": attachment_id},
        )
    except BudgetExhausted:
        return ActionOutcome(
            status="failed",
            vendor_ref=str(attachment_id),
            error="stored attachment exceeds attachment_max_bytes and cannot be verified",
            result={"attachment_id": attachment_id},
        )
    if hashlib.sha256(payload).hexdigest() != str(plan.request["sha256"]):
        return ActionOutcome(
            status="failed",
            vendor_ref=str(attachment_id),
            error="stored attachment SHA-256 does not match the uploaded content",
            result={"attachment_id": attachment_id},
        )
    return ActionOutcome(
        status="succeeded",
        vendor_ref=str(attachment_id),
        result={"attachment_id": attachment_id, "content_id": content_id},
    )


async def _associate_and_verify(
    connector: Any, plan: ActionPlan, field_id: int, attachment_id: int
) -> ActionOutcome:
    try:
        await _associate_attachment(connector, plan, field_id, attachment_id)
    except (Conflict, PermissionDenied) as exc:
        return ActionOutcome(
            status="failed",
            vendor_ref=str(attachment_id),
            error=f"association rejected after upload: {type(exc).__name__}",
            result={"attachment_id": attachment_id},
        )
    except (NotFound, OutcomeUnknown) as exc:
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=str(attachment_id),
            error=f"association unconfirmed: {type(exc).__name__}",
            result={"attachment_id": attachment_id},
        )
    return await _verify_attachment(connector, plan, field_id, attachment_id)


async def plan_upload_attachment(connector: Any, args: UploadAttachmentInput) -> ActionPlan:
    mapping = _mapping(connector, args.record_type)
    current = await connector.api.content(args.content_id)
    _check_version(current, args.expected_version)
    try:
        decoded = base64.b64decode(args.content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigError("Archer attachment content_base64 is not valid base64") from exc
    if len(decoded) > connector.config.attachment_max_bytes:
        raise ConfigError(
            f"Archer attachment exceeds attachment_max_bytes={connector.config.attachment_max_bytes}"
        )
    digest = hashlib.sha256(decoded).hexdigest()
    field_id = await _field_id(connector, mapping, args.field_name)
    duplicate = await _existing_attachment_with_digest(connector, current, field_id, digest)
    return ActionPlan(
        action="upload_attachment",
        target_ref=str(args.content_id),
        diff=(
            {}
            if duplicate is not None
            else {"attachment": {"filename": args.filename, "sha256": digest}}
        ),
        preconditions={"version": args.expected_version},
        idempotency_key=action_identity(
            connector,
            "upload_attachment",
            f"{args.content_id}:{args.field_name}:{digest}",
        ),
        changed=duplicate is None,
        request={
            "content_id": args.content_id,
            "record_type": args.record_type,
            "field_name": args.field_name,
            "filename": args.filename,
            "content_base64": args.content_base64,
            "sha256": digest,
        },
    )


async def apply_upload_attachment(connector: Any, plan: ActionPlan) -> ActionOutcome:
    if not plan.changed:
        return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
    _require_write(connector)
    content_id = int(plan.request["content_id"])
    mapping = _mapping(connector, str(plan.request["record_type"]))
    field_id = await _field_id(connector, mapping, str(plan.request["field_name"]))
    current = await connector.api.content(content_id)
    _check_version(current, plan.preconditions["version"])
    try:
        uploaded = await connector.api.upload_attachment(
            content_id,
            field_id,
            str(plan.request["filename"]),
            str(plan.request["content_base64"]),
        )
    except OutcomeUnknown as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    if uploaded.get("Id") is None:
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=plan.target_ref,
            error="Archer upload response has no Id",
        )
    return await _associate_and_verify(connector, plan, field_id, int(uploaded["Id"]))


async def reconcile_upload_attachment(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    # Never re-uploads: an uncertain upload is resolved by associating a known orphan, or by
    # finding a field attachment with the same filename and SHA-256.
    content_id = int(plan.request["content_id"])
    digest = str(plan.request["sha256"])
    known = outcome.result.get("attachment_id")
    try:
        mapping = _mapping(connector, str(plan.request["record_type"]))
        field_id = await _field_id(connector, mapping, str(plan.request["field_name"]))
        if known is not None:
            return await _associate_and_verify(connector, plan, field_id, int(known))
        current = await connector.api.content(content_id)
        for item in _field_attachments(current, field_id):
            if str(item.get("Name")) != str(plan.request["filename"]):
                continue
            attachment_id = int(item["Id"])
            if await _digest_matches(connector, attachment_id, digest):
                return ActionOutcome(
                    status="succeeded",
                    vendor_ref=str(attachment_id),
                    result={"attachment_id": attachment_id, "content_id": content_id},
                )
    except (NotFound, OutcomeUnknown) as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)


async def plan_execute_data_feed(connector: Any, args: ExecuteDataFeedInput) -> ActionPlan:
    request = {
        "data_feed_guid": args.data_feed_guid,
        "include_reference_feeds": bool(args.include_reference_feeds),
    }
    return ActionPlan(
        action="execute_data_feed",
        target_ref=args.data_feed_guid,
        diff=dict(request),
        preconditions={},
        idempotency_key=action_identity(
            connector,
            "execute_data_feed",
            f"{args.data_feed_guid}:{bool(args.include_reference_feeds)}",
        ),
        changed=True,
        request=request,
    )


async def apply_execute_data_feed(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    try:
        response = await connector.api.execute_data_feed(
            str(plan.request["data_feed_guid"]),
            bool(plan.request["include_reference_feeds"]),
        )
    except OutcomeUnknown as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    return ActionOutcome(
        status="accepted_async", vendor_ref=plan.target_ref, result={"response": response}
    )


async def reconcile_execute_data_feed(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    runs = await connector.api.data_feed_history()
    guid = str(plan.request["data_feed_guid"])
    for run in runs:
        # [UNVERIFIED] Data-feed history key and terminal status spelling vary by release.
        run_guid = run.get("DataFeedGuid") or run.get("Guid") or run.get("data_feed_guid")
        if str(run_guid) != guid:
            continue
        status = str(run.get("Status") or run.get("StatusName") or run.get("status") or "").lower()
        if status in {"completed", "success", "succeeded"}:
            return ActionOutcome(status="succeeded", vendor_ref=guid, result={"run": run})
        return ActionOutcome(status="accepted_async", vendor_ref=guid, result={"run": run})
    return ActionOutcome(status="outcome_unknown", vendor_ref=guid)


async def plan_delete(connector: Any, args: DeleteContentInput) -> ActionPlan:
    current = await connector.api.content(args.content_id)
    _check_version(current, args.expected_version)
    current_level = current.get("LevelId")
    if current_level is not None and int(current_level) != args.level_id:
        raise StalePlan(
            f"Archer content LevelId {current_level} does not match expected {args.level_id}"
        )
    return ActionPlan(
        action="delete_content",
        target_ref=str(args.content_id),
        diff={"delete": args.content_id},
        preconditions={"version": args.expected_version},
        idempotency_key=action_identity(
            connector, "delete_content", f"{args.content_id}:{args.expected_version}"
        ),
        changed=True,
        request={"content_id": args.content_id, "level_id": args.level_id},
    )


async def apply_delete(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    _require_destructive(connector)
    try:
        await connector.api.delete_content(int(plan.request["content_id"]))
    except OutcomeUnknown as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    return await reconcile_delete(
        connector,
        plan,
        ActionOutcome(status="succeeded", vendor_ref=plan.target_ref),
    )


async def reconcile_delete(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    """Succeed only when the content is proven absent (a NotFound read after the delete)."""
    try:
        await connector.api.content(int(plan.request["content_id"]))
    except NotFound:
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
    except OutcomeUnknown as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    return ActionOutcome(
        status="outcome_unknown",
        vendor_ref=plan.target_ref,
        error="content is still present after delete",
    )
