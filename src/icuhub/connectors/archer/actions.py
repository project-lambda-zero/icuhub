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


def _classify_read_back(
    current: dict[str, Any], encoded: dict[str, dict[str, Any]]
) -> tuple[str, str] | None:
    """Return None when every approved value reads back, else (status, reason).

    A present field whose stored value differs disproves the approved state (failed). A field
    absent from a readable record is omitted or permission-hidden, so the data cannot establish
    the state (unverified). A definitive disproof outranks an omission.
    """
    contents = _field_contents(current)
    omitted = False
    for field_id, desired_field in encoded.items():
        current_field = contents.get(str(field_id))
        if not isinstance(current_field, dict):
            omitted = True
            continue
        if _stored_value(current_field) != _desired_value(desired_field):
            return "failed", "read-back does not match the requested field values"
    if omitted:
        return "unverified", "read-back omitted approved fields; state cannot be established"
    return None


async def _read_back_fields(
    connector: Any, content_id: int, encoded: dict[str, dict[str, Any]]
) -> tuple[str, str] | None:
    """Return None when the mapped fields read back as requested, else (status, reason).

    A failed read is a reconcilable outcome_unknown.
    """
    try:
        current = await connector.api.content(content_id)
    except (NotFound, OutcomeUnknown) as exc:
        return "outcome_unknown", f"read-back failed: {type(exc).__name__}"
    return _classify_read_back(current, encoded)


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
    read_back = await _read_back_fields(connector, content_id, encoded)
    if read_back is not None:
        status, reason = read_back
        return ActionOutcome(
            status=status, vendor_ref=str(content_id), error=reason, result={"content_id": content_id}
        )
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
    encoded = await connector.api.encode_fields(
        int(plan.request["level_id"]), plan.request["field_values"]
    )
    read_back = await _read_back_fields(connector, content_id, encoded)
    if read_back is not None:
        status, reason = read_back
        return ActionOutcome(
            status=status, vendor_ref=str(content_id), error=reason, result={"content_id": content_id}
        )
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
    read_back = await _read_back_fields(connector, content_id, encoded)
    if read_back is not None:
        status, reason = read_back
        return ActionOutcome(status=status, vendor_ref=plan.target_ref, error=reason)
    return ActionOutcome(
        status="succeeded",
        vendor_ref=plan.target_ref,
        result={"content_id": content_id, "response": response},
    )


async def reconcile_update(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    content_id = int(plan.request["content_id"])
    encoded = await connector.api.encode_fields(
        int(plan.request["level_id"]), plan.request["field_values"]
    )
    read_back = await _read_back_fields(connector, content_id, encoded)
    if read_back is not None:
        status, reason = read_back
        return ActionOutcome(status=status, vendor_ref=plan.target_ref, error=reason)
    return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)


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
    existing_ids = [int(item["Id"]) for item in _field_attachments(current, field_id)]
    if attachment_id in existing_ids:
        return
    # Type 11 FieldContents value is a list of attachment ids (vendor content example).
    encoded = {str(field_id): {"Type": 11, "Value": [*existing_ids, attachment_id], "FieldId": field_id}}
    await connector.api.update_content(
        content_id,
        mapping.level_id,
        encoded,
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
                status="failed",
                vendor_ref=str(attachment_id),
                error="attachment is absent from the content after the association write",
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
            status="unverified",
            vendor_ref=str(attachment_id),
            error="stored attachment exceeds attachment_max_bytes; its bytes cannot be verified",
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
            status="outcome_unknown",
            vendor_ref=str(attachment_id),
            error=f"association unconfirmed after upload: {type(exc).__name__}",
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
            "is_sensitive": bool(args.is_sensitive),
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
        attachment_id = await connector.api.upload_attachment(
            str(plan.request["filename"]),
            str(plan.request["content_base64"]),
            bool(plan.request["is_sensitive"]),
        )
    except OutcomeUnknown as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    return await _associate_and_verify(connector, plan, field_id, attachment_id)


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


_DATA_FEED_STATUS_NAMES: dict[str, int] = {
    "Running": 1,
    "Completed": 2,
    "Faulted": 3,
    "Warning": 4,
    "Terminating": 5,
    "Terminated": 6,
    "Pending": 7,
}
# [UNVERIFIED] Status code enum from the vendor datafeed history docs. Terminating is transitional,
# so it stays accepted_async rather than a terminal failure.
_DATA_FEED_CODE_OUTCOMES: dict[int, str] = {
    1: "accepted_async",
    2: "succeeded",
    3: "failed",
    4: "failed",
    5: "accepted_async",
    6: "failed",
    7: "accepted_async",
}


def _history_id(run: dict[str, Any]) -> int | None:
    value = run.get("HistoryId", run.get("Id"))
    return int(value) if value is not None else None


def _history_ids(runs: list[dict[str, Any]]) -> set[int]:
    return {history_id for run in runs if (history_id := _history_id(run)) is not None}


def _data_feed_run_outcome(run: dict[str, Any]) -> str | None:
    raw = run.get("Status")
    if raw is None:
        raw = run.get("StatusName")
    if isinstance(raw, int) and not isinstance(raw, bool):
        code: int | None = raw
    else:
        code = _DATA_FEED_STATUS_NAMES.get(str(raw))
    return _DATA_FEED_CODE_OUTCOMES.get(code) if code is not None else None


async def apply_execute_data_feed(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    guid = str(plan.request["data_feed_guid"])
    # Baseline run ids taken before the send so reconcile binds only to runs this send creates.
    try:
        baseline = await connector.api.data_feed_history(guid)
    except OutcomeUnknown as exc:
        return ActionOutcome(
            status="failed",
            vendor_ref=plan.target_ref,
            error=f"baseline history read failed; data feed not executed: {exc}",
        )
    result: dict[str, Any] = {"pre_send_history_ids": sorted(_history_ids(baseline))}
    try:
        response = await connector.api.execute_data_feed(
            guid,
            bool(plan.request["include_reference_feeds"]),
        )
    except OutcomeUnknown as exc:
        return ActionOutcome(
            status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc), result=result
        )
    return ActionOutcome(
        status="accepted_async",
        vendor_ref=plan.target_ref,
        result={**result, "response": response},
    )


async def reconcile_execute_data_feed(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    guid = str(plan.request["data_feed_guid"])
    pre_send = outcome.result.get("pre_send_history_ids")
    if pre_send is None:
        return ActionOutcome(
            status="outcome_unknown", vendor_ref=guid, error="no pre-send history baseline recorded"
        )
    try:
        runs = await connector.api.data_feed_history(guid)
        baseline = set(pre_send)
        new_runs = [
            run
            for run in runs
            if (history_id := _history_id(run)) is not None and history_id not in baseline
        ]
        if not new_runs:
            return ActionOutcome(
                status="outcome_unknown", vendor_ref=guid, error="no run appeared after the send"
            )
        run = max(new_runs, key=lambda item: _history_id(item) or -1)
        run_id = _history_id(run)
        if run_id is None:  # Defensive: new_runs already excludes this case.
            return ActionOutcome(status="outcome_unknown", vendor_ref=guid, error="run has no history Id")
        status = _data_feed_run_outcome(run)
        if status is None:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=guid,
                error="unrecognized data-feed run status",
                result={"run": run},
            )
        result: dict[str, Any] = {"run": run}
        if status not in {"succeeded", "accepted_async"}:
            result["messages"] = await connector.api.data_feed_history_messages(run_id)
    except OutcomeUnknown as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=guid, error=str(exc))
    return ActionOutcome(status=status, vendor_ref=guid, result=result)


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
    """Succeed only when the content is proven absent (a NotFound read after the delete).

    A readable record after the delete definitively disproves the approved state (failed). A
    failed read leaves the state reconcilable (outcome_unknown).
    """
    try:
        await connector.api.content(int(plan.request["content_id"]))
    except NotFound:
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
    except OutcomeUnknown as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    return ActionOutcome(
        status="failed",
        vendor_ref=plan.target_ref,
        error="content is still present after delete",
    )
