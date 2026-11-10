"""Plan, apply, and reconcile tests for Archer content actions."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors.archer.actions import (
    action_identity,
    apply_create,
    apply_delete,
    apply_execute_data_feed,
    apply_update,
    apply_upload_attachment,
    plan_create,
    plan_delete,
    plan_execute_data_feed,
    plan_update,
    plan_upload_attachment,
    reconcile_create,
    reconcile_delete,
    reconcile_execute_data_feed,
    reconcile_update,
    reconcile_upload_attachment,
)
from icuhub.connectors.archer.models import (
    CreateFindingOrExceptionInput,
    DeleteContentInput,
    ExecuteDataFeedInput,
    UpdateFindingOrExceptionInput,
    UploadAttachmentInput,
)
from icuhub.kit import ActionOutcome, ConfigError, StalePlan
from icuhub.kit.testing import RouteTransport

from .conftest import make_archer

FIXTURES = Path(__file__).parents[2] / "fixtures" / "archer" / "actions"
LOGIN = ("POST", "/platformapi/core/security/login")
LOGIN_RESPONSE = {
    "status": 200,
    "json": {"IsSuccessful": True, "RequestedObject": {"SessionToken": "tok"}},
}
RECORD_TYPES = {
    "findings": {
        "application_id": 7,
        "level_id": 8,
        "field_ids": {"ExternalCorrelationId": 101, "Title": 102, "Evidence": 103},
        "correlation_field": "ExternalCorrelationId",
        "time_field": "LastUpdated",
    }
}


def load_json(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def load_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def json_response(name: str, status: int = 200) -> dict[str, Any]:
    return {"status": status, "json": load_json(name)}


def make_connector(routes: dict[tuple[str, str], Any], **config_overrides: Any):
    config = {"record_types": RECORD_TYPES, "write_enabled": True, "destructive_enabled": True}
    config.update(config_overrides)
    return make_archer(RouteTransport({LOGIN: LOGIN_RESPONSE, **routes}), config_overrides=config)


def create_args() -> CreateFindingOrExceptionInput:
    return CreateFindingOrExceptionInput(
        record_type="findings",
        correlation_value="case-1",
        field_values={"Title": "Example finding"},
    )


def update_args(**overrides: Any) -> UpdateFindingOrExceptionInput:
    values = {
        "record_type": "findings",
        "content_id": 42,
        "expected_version": 3,
        "field_values": {"Title": "After"},
    }
    values.update(overrides)
    return UpdateFindingOrExceptionInput(**values)


def attachment_args(**overrides: Any) -> UploadAttachmentInput:
    values = {
        "record_type": "findings",
        "content_id": 42,
        "field_name": "Evidence",
        "filename": "evidence.txt",
        "content_base64": base64.b64encode(b"evidence").decode("ascii"),
        "expected_version": 3,
    }
    values.update(overrides)
    return UploadAttachmentInput(**values)


def feed_args(**overrides: Any) -> ExecuteDataFeedInput:
    values = {
        "data_feed_guid": "feed-guid-1",
        "approved_plan_hash": "placeholder",
        "include_reference_feeds": True,
    }
    values.update(overrides)
    return ExecuteDataFeedInput(**values)


def delete_args(**overrides: Any) -> DeleteContentInput:
    values = {
        "content_id": 42,
        "level_id": 8,
        "expected_version": 3,
        "approved_plan_hash": "placeholder",
    }
    values.update(overrides)
    return DeleteContentInput(**values)


def content_with(title: str = "Before", version: int = 3, filename: str | None = None) -> dict[str, Any]:
    response = copy.deepcopy(load_json("content.json"))
    content = response["RequestedObject"]
    content["Version"] = version
    content["FieldContents"]["102"]["Value"] = title
    if filename is not None:
        content["FieldContents"]["103"] = {
            "Type": 11,
            "Value": [{"Id": 901, "Name": filename}],
            "FieldId": 103,
        }
    return response


def test_action_identity_is_tenant_scoped_and_deterministic() -> None:
    connector = make_connector({})
    expected = hashlib.sha256(b"test-tenant\x1fcreate_finding_or_exception\x1fcase-1").hexdigest()
    assert action_identity(connector, "create_finding_or_exception", "case-1") == expected
    assert action_identity(connector, "create_finding_or_exception", "case-1") == expected
    assert action_identity(connector, "update_finding_or_exception", "case-1") != expected


def test_create_is_no_op_when_correlation_exists() -> None:
    connector = make_connector({
        ("POST", "/ws/search.asmx"): {"status": 200, "text": load_text("search_existing.xml")}
    })
    args = create_args()
    first = asyncio.run(plan_create(connector, args))
    second = asyncio.run(plan_create(connector, args))
    assert first.changed is False
    assert first.target_ref == "42"
    assert first.diff == {}
    assert first.plan_hash == second.plan_hash
    outcome = asyncio.run(apply_create(connector, first))
    assert outcome.status == "no_op"
    assert outcome.vendor_ref == "42"


def test_create_apply_sends_level_and_encoded_field_contents() -> None:
    seen: dict[str, Any] = {}

    def create(request: Any) -> dict[str, Any]:
        seen.update(json.loads(request.content))
        return json_response("create_response.json", 201)

    connector = make_connector({
        ("POST", "/ws/search.asmx"): {"status": 200, "text": load_text("search_empty.xml")},
        ("POST", "/platformapi/core/system/fielddefinition/level/8"): json_response("fields.json"),
        ("POST", "/platformapi/core/content"): create,
        ("POST", "/platformapi/core/content/contentid"): {
            "status": 200,
            "json": content_with(title="Example finding"),
        },
    })
    args = create_args()
    first = asyncio.run(plan_create(connector, args))
    second = asyncio.run(plan_create(connector, args))
    assert first.changed is True
    assert first.diff == {"create": {"Title": "Example finding"}}
    assert first.request["field_values"] == {
        "Title": "Example finding",
        "ExternalCorrelationId": "case-1",
    }
    assert first.plan_hash == second.plan_hash
    outcome = asyncio.run(apply_create(connector, first))
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "42"
    assert outcome.result == {"content_id": 42}
    assert seen["LevelId"] == 8
    assert seen["FieldContents"]["101"] == {
        "Type": 1,
        "Value": "case-1",
        "FieldId": 101,
    }
    assert seen["FieldContents"]["102"]["Value"] == "Example finding"


def test_create_reconcile_finds_natural_key() -> None:
    responses = iter(("search_empty.xml", "search_existing.xml"))
    connector = make_connector({
        ("POST", "/ws/search.asmx"): lambda _request: {"status": 200, "text": load_text(next(responses))}
    })
    args = create_args()
    plan = asyncio.run(plan_create(connector, args))
    outcome = asyncio.run(reconcile_create(connector, plan, ActionOutcome(status="outcome_unknown")))
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "42"
    assert outcome.result == {"content_id": 42}


def test_create_reconcile_without_match_is_outcome_unknown() -> None:
    connector = make_connector({
        ("POST", "/ws/search.asmx"): {"status": 200, "text": load_text("search_empty.xml")}
    })
    args = create_args()
    plan = asyncio.run(plan_create(connector, args))
    outcome = asyncio.run(reconcile_create(connector, plan, ActionOutcome(status="succeeded")))
    assert outcome.status == "outcome_unknown"


def test_update_rejects_stale_version() -> None:
    connector = make_connector({
        ("POST", "/platformapi/core/content/contentid"): {"status": 200, "json": content_with(version=4)}
    })
    with pytest.raises(StalePlan):
        asyncio.run(plan_update(connector, update_args()))


def test_update_no_change_is_no_op() -> None:
    connector = make_connector(
        {
            ("POST", "/platformapi/core/content/contentid"): {"status": 200, "json": content_with()},
            ("POST", "/platformapi/core/system/fielddefinition/level/8"): json_response("fields.json"),
        },
        write_enabled=False,
    )
    args = update_args(field_values={"Title": "Before"})
    plan = asyncio.run(plan_update(connector, args))
    assert plan.changed is False
    assert plan.diff == {}
    outcome = asyncio.run(apply_update(connector, plan))
    assert outcome.status == "no_op"


def test_update_apply_sends_expected_version_and_only_changed_fields() -> None:
    seen: dict[str, Any] = {}
    state: dict[str, Any] = {"title": "Before", "version": 3}

    def read_content(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": content_with(**state)}

    def update(request: Any) -> dict[str, Any]:
        seen.update(json.loads(request.content))
        state.update(title="After", version=4)
        return json_response("update_response.json")

    connector = make_connector({
        ("POST", "/platformapi/core/content/contentid"): read_content,
        ("POST", "/platformapi/core/system/fielddefinition/level/8"): json_response("fields.json"),
        ("PUT", "/platformapi/core/content"): update,
    })
    args = update_args()
    first = asyncio.run(plan_update(connector, args))
    second = asyncio.run(plan_update(connector, args))
    assert first.changed is True
    assert first.diff == {"Title": {"from": "Before", "to": "After"}}
    assert first.preconditions == {"version": 3}
    assert first.plan_hash == second.plan_hash
    outcome = asyncio.run(apply_update(connector, first))
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "42"
    assert seen["Id"] == 42
    assert seen["LevelId"] == 8
    assert seen["Version"] == 3
    assert set(seen["FieldContents"]) == {"102"}
    assert seen["FieldContents"]["102"]["Value"] == "After"


def test_update_reconcile_succeeds_when_requested_values_are_present() -> None:
    responses = iter((content_with(), content_with(title="After", version=4)))
    connector = make_connector({
        ("POST", "/platformapi/core/content/contentid"): lambda _request: {
            "status": 200,
            "json": next(responses),
        },
        ("POST", "/platformapi/core/system/fielddefinition/level/8"): json_response("fields.json"),
    })
    args = update_args()
    plan = asyncio.run(plan_update(connector, args))
    outcome = asyncio.run(reconcile_update(connector, plan, ActionOutcome(status="outcome_unknown")))
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "42"


def test_update_reconcile_without_requested_values_is_outcome_unknown() -> None:
    connector = make_connector({
        ("POST", "/platformapi/core/content/contentid"): {"status": 200, "json": content_with()},
        ("POST", "/platformapi/core/system/fielddefinition/level/8"): json_response("fields.json"),
    })
    args = update_args()
    plan = asyncio.run(plan_update(connector, args))
    outcome = asyncio.run(reconcile_update(connector, plan, ActionOutcome(status="outcome_unknown")))
    assert outcome.status == "outcome_unknown"


def content_with_attachments(attachments: list[dict[str, Any]], version: int) -> dict[str, Any]:
    response = content_with(version=version)
    if attachments:
        response["RequestedObject"]["FieldContents"]["103"] = {
            "Type": 11,
            "Value": attachments,
            "FieldId": 103,
        }
    return response


def attachment_routes(
    state: dict[str, Any],
    *,
    uploads: list[dict[str, Any]],
    puts: list[dict[str, Any]],
    payloads: dict[int, bytes],
) -> dict[tuple[str, str], Any]:
    """Stateful content routes: an upload bumps Version; a PUT replaces the attachment field."""

    def read(_request: Any) -> dict[str, Any]:
        return {
            "status": 200,
            "json": content_with_attachments(state["attachments"], state["version"]),
        }

    def upload(request: Any) -> dict[str, Any]:
        uploads.append(json.loads(request.content))
        state["version"] += 1
        return json_response("upload_response.json", 201)

    def put(request: Any) -> dict[str, Any]:
        body = json.loads(request.content)
        puts.append(body)
        state["attachments"] = body["FieldContents"]["103"]["Value"]
        state["version"] = body["Version"] + 1
        return json_response("update_response.json")

    routes: dict[tuple[str, str], Any] = {
        ("POST", "/platformapi/core/content/contentid"): read,
        ("POST", "/platformapi/core/content/attachment"): upload,
        ("PUT", "/platformapi/core/content"): put,
    }
    for attachment_id, payload in payloads.items():
        routes[("POST", f"/platformapi/core/content/attachment/{attachment_id}")] = {
            "status": 200,
            "text": payload.decode("utf-8"),
        }
    return routes


def test_upload_attachment_plan_and_apply_use_decoded_digest_and_field_id() -> None:
    state: dict[str, Any] = {"version": 3, "attachments": []}
    uploads: list[dict[str, Any]] = []
    puts: list[dict[str, Any]] = []
    connector = make_connector(
        attachment_routes(state, uploads=uploads, puts=puts, payloads={901: b"evidence"})
    )
    args = attachment_args()
    first = asyncio.run(plan_upload_attachment(connector, args))
    second = asyncio.run(plan_upload_attachment(connector, args))
    digest = hashlib.sha256(b"evidence").hexdigest()
    assert first.changed is True
    assert first.diff == {"attachment": {"filename": "evidence.txt", "sha256": digest}}
    assert first.plan_hash == second.plan_hash
    outcome = asyncio.run(apply_upload_attachment(connector, first))
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "901"
    assert outcome.result == {"attachment_id": 901, "content_id": 42}
    assert uploads[0]["ContentId"] == 42
    assert uploads[0]["FieldId"] == 103
    assert uploads[0]["FileName"] == "evidence.txt"
    assert uploads[0]["FileContent"] == args.content_base64
    assert puts[0]["FieldContents"]["103"] == {
        "Type": 11,
        "Value": [{"Id": 901, "Name": "evidence.txt"}],
        "FieldId": 103,
    }


def test_upload_attachment_duplicate_evidence_is_no_op_without_upload() -> None:
    state: dict[str, Any] = {"version": 3, "attachments": [{"Id": 901, "Name": "evidence.txt"}]}
    uploads: list[dict[str, Any]] = []
    puts: list[dict[str, Any]] = []
    connector = make_connector(
        attachment_routes(state, uploads=uploads, puts=puts, payloads={901: b"evidence"})
    )
    args = attachment_args()
    plan = asyncio.run(plan_upload_attachment(connector, args))
    assert plan.changed is False
    assert plan.diff == {}
    outcome = asyncio.run(apply_upload_attachment(connector, plan))
    assert outcome.status == "no_op"
    assert uploads == []
    assert puts == []


def test_upload_attachment_preserves_existing_attachment_ids() -> None:
    state: dict[str, Any] = {"version": 3, "attachments": [{"Id": 900, "Name": "old.txt"}]}
    uploads: list[dict[str, Any]] = []
    puts: list[dict[str, Any]] = []
    connector = make_connector(
        attachment_routes(
            state, uploads=uploads, puts=puts, payloads={900: b"other", 901: b"evidence"}
        )
    )
    args = attachment_args()
    plan = asyncio.run(plan_upload_attachment(connector, args))
    assert plan.changed is True
    outcome = asyncio.run(apply_upload_attachment(connector, plan))
    assert outcome.status == "succeeded"
    assert puts[0]["FieldContents"]["103"]["Value"] == [
        {"Id": 900, "Name": "old.txt"},
        {"Id": 901, "Name": "evidence.txt"},
    ]


def test_upload_attachment_association_uses_version_current_after_upload() -> None:
    state: dict[str, Any] = {"version": 3, "attachments": []}
    uploads: list[dict[str, Any]] = []
    puts: list[dict[str, Any]] = []
    connector = make_connector(
        attachment_routes(state, uploads=uploads, puts=puts, payloads={901: b"evidence"})
    )
    args = attachment_args()
    plan = asyncio.run(plan_upload_attachment(connector, args))
    assert plan.preconditions == {"version": 3}
    outcome = asyncio.run(apply_upload_attachment(connector, plan))
    assert outcome.status == "succeeded"
    # The upload advanced Version to 4 in this fixture, so the association must use 4.
    assert puts[0]["Version"] == 4


def test_upload_attachment_hash_mismatch_after_write_is_failed() -> None:
    state: dict[str, Any] = {"version": 3, "attachments": []}
    uploads: list[dict[str, Any]] = []
    puts: list[dict[str, Any]] = []
    connector = make_connector(
        attachment_routes(state, uploads=uploads, puts=puts, payloads={901: b"tampered"})
    )
    args = attachment_args()
    plan = asyncio.run(plan_upload_attachment(connector, args))
    outcome = asyncio.run(apply_upload_attachment(connector, plan))
    assert outcome.status == "failed"
    assert outcome.vendor_ref == "901"
    assert outcome.result == {"attachment_id": 901}
    assert "SHA-256" in (outcome.error or "")


def test_upload_attachment_orphan_is_associated_and_not_reuploaded() -> None:
    state: dict[str, Any] = {"version": 3, "attachments": []}
    uploads: list[dict[str, Any]] = []
    puts: list[dict[str, Any]] = []
    connector = make_connector(
        attachment_routes(state, uploads=uploads, puts=puts, payloads={901: b"evidence"})
    )
    args = attachment_args()
    plan = asyncio.run(plan_upload_attachment(connector, args))
    orphaned = ActionOutcome(
        status="outcome_unknown",
        vendor_ref="42",
        error="timeout",
        result={"attachment_id": 901},
    )
    outcome = asyncio.run(reconcile_upload_attachment(connector, plan, orphaned))
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "901"
    assert uploads == []
    assert puts[0]["Version"] == 3
    assert puts[0]["FieldContents"]["103"]["Value"] == [{"Id": 901, "Name": "evidence.txt"}]


def test_upload_attachment_reconcile_with_mismatched_bytes_is_outcome_unknown() -> None:
    state: dict[str, Any] = {"version": 3, "attachments": [{"Id": 901, "Name": "evidence.txt"}]}
    uploads: list[dict[str, Any]] = []
    puts: list[dict[str, Any]] = []
    connector = make_connector(
        attachment_routes(state, uploads=uploads, puts=puts, payloads={901: b"tampered"})
    )
    args = attachment_args()
    plan = asyncio.run(plan_upload_attachment(connector, args))
    outcome = asyncio.run(
        reconcile_upload_attachment(connector, plan, ActionOutcome(status="outcome_unknown"))
    )
    assert outcome.status == "outcome_unknown"
    assert uploads == []
    assert puts == []


def test_update_read_back_mismatch_is_outcome_unknown() -> None:
    connector = make_connector({
        ("POST", "/platformapi/core/content/contentid"): {"status": 200, "json": content_with()},
        ("POST", "/platformapi/core/system/fielddefinition/level/8"): json_response("fields.json"),
        ("PUT", "/platformapi/core/content"): json_response("update_response.json"),
    })
    args = update_args()
    plan = asyncio.run(plan_update(connector, args))
    outcome = asyncio.run(apply_update(connector, plan))
    assert outcome.status == "outcome_unknown"


def test_delete_without_absence_proof_is_outcome_unknown() -> None:
    connector = make_connector({
        ("POST", "/platformapi/core/content/contentid"): {"status": 200, "json": content_with()},
        ("DELETE", "/platformapi/core/content/42"): {"status": 204},
    })
    args = delete_args()
    plan = asyncio.run(plan_delete(connector, args))
    outcome = asyncio.run(apply_delete(connector, plan))
    assert outcome.status == "outcome_unknown"
    assert outcome.vendor_ref == "42"


def test_upload_attachment_reconcile_finds_filename_with_matching_digest() -> None:
    state: dict[str, Any] = {"version": 3, "attachments": [{"Id": 901, "Name": "evidence.txt"}]}
    uploads: list[dict[str, Any]] = []
    puts: list[dict[str, Any]] = []
    connector = make_connector(
        attachment_routes(state, uploads=uploads, puts=puts, payloads={901: b"evidence"})
    )
    args = attachment_args()
    plan = asyncio.run(plan_upload_attachment(connector, args))
    assert plan.changed is False
    outcome = asyncio.run(
        reconcile_upload_attachment(connector, plan, ActionOutcome(status="outcome_unknown"))
    )
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "901"
    assert uploads == []
    assert puts == []


def test_upload_attachment_reconcile_without_filename_is_outcome_unknown() -> None:
    connector = make_connector({
        ("POST", "/platformapi/core/content/contentid"): {"status": 200, "json": content_with()}
    })
    args = attachment_args()
    plan = asyncio.run(plan_upload_attachment(connector, args))
    outcome = asyncio.run(
        reconcile_upload_attachment(connector, plan, ActionOutcome(status="outcome_unknown"))
    )
    assert outcome.status == "outcome_unknown"


def test_upload_attachment_rejects_stale_version() -> None:
    connector = make_connector({
        ("POST", "/platformapi/core/content/contentid"): {"status": 200, "json": content_with(version=4)}
    })
    with pytest.raises(StalePlan):
        asyncio.run(plan_upload_attachment(connector, attachment_args()))


@pytest.mark.parametrize(
    ("payload", "max_bytes"),
    [("not valid base64!", 1024), (base64.b64encode(b"12345").decode("ascii"), 4)],
)
def test_upload_attachment_rejects_invalid_or_oversize_base64(payload: str, max_bytes: int) -> None:
    connector = make_connector(
        {("POST", "/platformapi/core/content/contentid"): {"status": 200, "json": content_with()}},
        attachment_max_bytes=max_bytes,
    )
    with pytest.raises(ConfigError):
        asyncio.run(plan_upload_attachment(connector, attachment_args(content_base64=payload)))


def test_data_feed_apply_returns_accepted_async() -> None:
    seen: dict[str, Any] = {}

    def execute(request: Any) -> dict[str, Any]:
        seen.update(json.loads(request.content))
        return json_response("data_feed_execute_response.json", 202)

    connector = make_connector({("POST", "/platformapi/core/datafeed/execution"): execute})
    args = feed_args()
    first = asyncio.run(plan_execute_data_feed(connector, args))
    second = asyncio.run(plan_execute_data_feed(connector, args))
    assert first.changed is True
    assert first.diff == {"data_feed_guid": "feed-guid-1", "include_reference_feeds": True}
    assert first.request == first.diff
    assert first.preconditions == {}
    assert first.plan_hash == second.plan_hash
    assert "approved_plan_hash" not in first.diff
    assert "approved_plan_hash" not in first.preconditions
    assert "approved_plan_hash" not in first.request
    outcome = asyncio.run(apply_execute_data_feed(connector, first))
    assert outcome.status == "accepted_async"
    assert outcome.vendor_ref == "feed-guid-1"
    assert seen == {"DataFeedGuid": "feed-guid-1", "IsReferenceFeedsIncluded": True}


@pytest.mark.parametrize(
    ("fixture", "status"),
    [
        ("data_feed_history_completed.json", "succeeded"),
        ("data_feed_history_running.json", "accepted_async"),
        ("data_feed_history_empty.json", "outcome_unknown"),
    ],
)
def test_data_feed_reconciles_run_history(fixture: str, status: str) -> None:
    connector = make_connector({
        ("POST", "/platformapi/core/datafeed/history"): json_response(fixture)
    })
    args = feed_args()
    plan = asyncio.run(plan_execute_data_feed(connector, args))
    outcome = asyncio.run(
        reconcile_execute_data_feed(connector, plan, ActionOutcome(status="accepted_async"))
    )
    assert outcome.status == status
    assert outcome.vendor_ref == "feed-guid-1"


def test_delete_apply_reconciles_not_found() -> None:
    reads = 0

    def content(_request: Any) -> dict[str, Any]:
        nonlocal reads
        reads += 1
        if reads <= 2:
            return {"status": 200, "json": content_with()}
        return {"status": 404, "json": {"IsSuccessful": False}}

    deleted: list[str] = []

    def delete(request: Any) -> dict[str, Any]:
        deleted.append(request.url.path)
        return {"status": 204}

    connector = make_connector({
        ("POST", "/platformapi/core/content/contentid"): content,
        ("DELETE", "/platformapi/core/content/42"): delete,
    })
    args = delete_args()
    first = asyncio.run(plan_delete(connector, args))
    second = asyncio.run(plan_delete(connector, args))
    assert first.changed is True
    assert first.diff == {"delete": 42}
    assert first.request == {"content_id": 42, "level_id": 8}
    assert first.plan_hash == second.plan_hash
    assert "approved_plan_hash" not in first.diff
    assert "approved_plan_hash" not in first.preconditions
    assert "approved_plan_hash" not in first.request
    outcome = asyncio.run(apply_delete(connector, first))
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "42"
    assert deleted == ["/platformapi/core/content/42"]
    reconciled = asyncio.run(reconcile_delete(connector, first, outcome))
    assert reconciled.status == "succeeded"
    assert reconciled.vendor_ref == "42"


def test_delete_reconcile_with_content_present_is_outcome_unknown() -> None:
    connector = make_connector({
        ("POST", "/platformapi/core/content/contentid"): {"status": 200, "json": content_with()}
    })
    args = delete_args()
    plan = asyncio.run(plan_delete(connector, args))
    outcome = asyncio.run(reconcile_delete(connector, plan, ActionOutcome(status="outcome_unknown")))
    assert outcome.status == "outcome_unknown"


def test_write_gate_blocks_create_apply() -> None:
    connector = make_connector(
        {("POST", "/ws/search.asmx"): {"status": 200, "text": load_text("search_empty.xml")}},
        write_enabled=False,
    )
    args = create_args()
    plan = asyncio.run(plan_create(connector, args))
    with pytest.raises(ConfigError):
        asyncio.run(apply_create(connector, plan))


def test_destructive_gate_blocks_delete_apply() -> None:
    connector = make_connector(
        {("POST", "/platformapi/core/content/contentid"): {"status": 200, "json": content_with()}},
        destructive_enabled=False,
    )
    args = delete_args()
    plan = asyncio.run(plan_delete(connector, args))
    with pytest.raises(ConfigError):
        asyncio.run(apply_delete(connector, plan))
