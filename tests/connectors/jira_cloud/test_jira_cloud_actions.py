"""Action conformance for the Jira Cloud write paths, run through recorded transports.

Covers ``create_issue``, ``update_issue_fields``, ``add_comment``, ``update_comment``,
``transition_issue``, ``link_issue``, ``add_remote_link``, ``upload_attachment``,
``create_webhook``, ``delete_webhook``, ``refresh_webhook``, ``delete_issue``,
``delete_comment``, and ``delete_attachment``: plan, apply, no-op replay, stale-plan
preconditions, ``outcome_unknown`` after a transport timeout on a non-idempotent write,
reconcile, and the destructive gate. Requests are answered by ``RouteTransport``. Route
callables mutate synthetic issue, comment, attachment, remote-link, and webhook state so
reconcile observes the write. Plans run against routes with no write method, so any
plan-time write fails the test. Timeouts are only simulated on non-idempotent writes:
the kit retries ``idempotent_write`` requests, so those reconcile paths are exercised by
calling ``reconcile`` on a plan directly.
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Callable
from typing import Any, cast

import httpx2
import pytest

from icuhub.connectors._jira.models import (
    AddCommentInput,
    AttachmentInput,
    CreateIssueInput,
    CreateWebhookInput,
    DeleteAttachmentInput,
    DeleteCommentInput,
    DeleteIssueInput,
    DeleteWebhookInput,
    LinkIssueInput,
    RefreshWebhookInput,
    RemoteLinkInput,
    TransitionIssueInput,
    UpdateCommentInput,
    UpdateIssueInput,
)
from icuhub.connectors.jira_cloud.connector import JiraCloud
from icuhub.kit.errors import ConfigError, StalePlan
from icuhub.kit.testing import RouteTransport, make_connector
from icuhub.kit.types import ActionOutcome

BASE = "https://jira.example.test"
ACCOUNT = "svc-automation@example.test"
API_REF = "jira-api-token"
SECRETS = {API_REF: b"synthetic-api-token"}
OUTCOME = ActionOutcome(status="outcome_unknown")
API = "/rest/api/3"
ISSUE_KEY_PATH = f"{API}/issue/PROJ-1"
ISSUE_ID_PATH = f"{API}/issue/10001"
CREATE_PATH = f"{API}/issue"
SEARCH_PATH = f"{API}/search/jql"
COMMENT_PATH = f"{API}/issue/10001/comment"
COMMENT_ITEM_PATH = f"{API}/issue/10001/comment/777"
TRANSITIONS_PATH = f"{API}/issue/10001/transitions"
LINK_PATH = f"{API}/issueLink"
REMOTE_LINK_PATH = f"{API}/issue/10001/remotelink"
ATTACHMENTS_PATH = f"{API}/issue/10001/attachments"
ATTACHMENT_PATH = f"{API}/attachment/50001"
WEBHOOK_PATH = f"{API}/webhook"
WEBHOOK_REFRESH_PATH = f"{API}/webhook/refresh"
UPDATED = "2026-11-01T10:00:00.000+0000"
COMMENT_UPDATED = "2026-11-01T10:05:00.000+0000"
ATTACHMENT_CREATED = "2026-11-01T10:06:00.000+0000"
MARKER = "[icuhub-action:act-1]"
WEBHOOK_URL = "https://hooks.example.test/icuhub"
WEBHOOK_EVENT = "jira:issue_updated"
ATTACHMENT_BYTES = b"Synthetic evidence\n"
TRANSITION_LIST = {
    "transitions": [
        {"id": "21", "to": {"name": "In Progress"}},
        {"id": "31", "to": {"name": "Done"}},
    ]
}


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> JiraCloud:
    config = {
        "base_url": BASE,
        "auth_method": "basic",
        "account_email": ACCOUNT,
        "api_token": {"ref": API_REF},
        **config_extra,
    }
    return cast(JiraCloud, make_connector(JiraCloud, config, RouteTransport(routes), SECRETS))


def _spec(name: str) -> Any:
    return JiraCloud.actions()[name]


def _body(request: httpx2.Request) -> Any:
    return json.loads(request.content)


def _adf(text: str) -> dict[str, Any]:
    return {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}],
    }


def _issue_state(**overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "id": "10001",
        "key": "PROJ-1",
        "status": "To Do",
        "updated": UPDATED,
        "summary": "Original",
        "issuelinks": [],
        "attachment": [],
        "changelog": [],
        "deleted": False,
    }
    state.update(overrides)
    return state


def _issue_body(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": state["id"],
        "key": state["key"],
        "fields": {
            "status": {"name": state["status"]},
            "updated": state["updated"],
            "summary": state["summary"],
            "issuelinks": list(state["issuelinks"]),
            "attachment": list(state["attachment"]),
        },
        "changelog": {"histories": list(state["changelog"])},
    }


def _issue_route(state: dict[str, Any]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(_request: httpx2.Request) -> dict[str, Any]:
        return {"status": 200, "json": _issue_body(state)}

    return handler


def _issue_or_gone(state: dict[str, Any]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(_request: httpx2.Request) -> dict[str, Any]:
        if state["deleted"]:
            return {"status": 404}
        return {"status": 200, "json": _issue_body(state)}

    return handler


def _write(
    posts: list[httpx2.Request],
    *,
    status: int,
    body: Any = None,
    mutate: Callable[[httpx2.Request], None] | None = None,
    timeout: bool = False,
) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(request: httpx2.Request) -> dict[str, Any]:
        posts.append(request)
        if mutate is not None:
            mutate(request)
        if timeout:
            raise httpx2.ReadTimeout("synthetic read timeout after write")
        return {"status": status, "json": body} if body is not None else {"status": status}

    return handler


def _lists_route(items: list[dict[str, Any]]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(_request: httpx2.Request) -> dict[str, Any]:
        return {"status": 200, "json": list(items)}

    return handler


def _paged_route(key: str, items: list[dict[str, Any]]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(_request: httpx2.Request) -> dict[str, Any]:
        return {
            "status": 200,
            "json": {"startAt": 0, "maxResults": 50, "total": len(items), "isLast": True, key: list(items)},
        }

    return handler


def _single_or_gone(record: dict[str, Any], present: Callable[[], bool]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(_request: httpx2.Request) -> dict[str, Any]:
        if not present():
            return {"status": 404}
        return {"status": 200, "json": record}

    return handler


# --- create_issue -----------------------------------------------------------


def _create_args() -> CreateIssueInput:
    return CreateIssueInput(route_key="route-1", project_key="PROJ", issue_type="Task", summary="Triage")


def _created_issue_body() -> dict[str, Any]:
    return {
        "id": "10050",
        "key": "PROJ-7",
        "self": f"{BASE}/rest/api/3/issue/10050",
        "fields": {
            "updated": UPDATED,
            "status": {"name": "To Do", "statusCategory": {"key": "new"}},
        },
    }


def test_create_issue_posts_route_labelled_issue_and_succeeds() -> None:
    created: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", SEARCH_PATH): _paged_route("issues", created),
            ("POST", CREATE_PATH): _write(
                posts,
                status=201,
                body={"id": "10050", "key": "PROJ-7"},
                mutate=lambda _r: created.append({"id": "10050", "key": "PROJ-7"}),
            ),
            ("GET", f"{API}/issue/PROJ-7"): {"status": 200, "json": _created_issue_body()},
        }
    )
    spec = _spec("create_issue")

    plan = asyncio.run(spec.plan(connector, _create_args()))
    assert plan.changed is True
    assert plan.request["method"] == "POST"
    assert plan.request["path"] == CREATE_PATH
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_issue:PROJ-7"
    assert outcome.result["id"] == "10050"
    assert outcome.result["revision"] == f"10050:{UPDATED}"
    sent = _body(posts[0])["fields"]
    assert sent["project"] == {"key": "PROJ"}
    assert sent["summary"] == "Triage"
    assert sent["labels"] == [plan.preconditions["route_label"]]


def test_create_issue_replay_is_no_op_and_posts_nothing() -> None:
    created = [{"id": "10050", "key": "PROJ-7"}]
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", SEARCH_PATH): _paged_route("issues", created),
            ("POST", CREATE_PATH): _write(posts, status=201, body={"id": "10051", "key": "PROJ-8"}),
        }
    )
    spec = _spec("create_issue")

    plan = asyncio.run(spec.plan(connector, _create_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert plan.target_ref == "jira_issue:PROJ-7"
    assert outcome.status == "no_op"
    assert posts == []


def test_create_issue_timeout_after_post_reconciles_to_succeeded() -> None:
    created: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", SEARCH_PATH): _paged_route("issues", created),
            ("POST", CREATE_PATH): _write(
                posts,
                status=201,
                timeout=True,
                mutate=lambda _r: created.append({"id": "10050", "key": "PROJ-7"}),
            ),
            ("GET", f"{API}/issue/PROJ-7"): {"status": 200, "json": _created_issue_body()},
        }
    )
    spec = _spec("create_issue")
    plan = asyncio.run(spec.plan(connector, _create_args()))

    outcome = asyncio.run(spec.apply(connector, plan))
    assert outcome.status == "outcome_unknown"
    assert len(posts) == 1

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))
    assert reconciled.status == "succeeded"
    assert reconciled.vendor_ref == "jira_issue:PROJ-7"


def test_create_issue_timeout_without_created_issue_reconciles_to_failed() -> None:
    created: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", SEARCH_PATH): _paged_route("issues", created),
            ("POST", CREATE_PATH): _write(posts, status=201, timeout=True),
        }
    )
    spec = _spec("create_issue")
    plan = asyncio.run(spec.plan(connector, _create_args()))

    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"
    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "no issue carries the route label after the write timed out"


def test_create_issue_read_back_failure_is_outcome_unknown_then_reconciles() -> None:
    created: list[dict[str, Any]] = []
    healthy = {"value": False}

    def read_back(_request: httpx2.Request) -> dict[str, Any]:
        if not healthy["value"]:
            return {"status": 503, "json": {"errorMessages": ["temporarily unavailable"]}}
        return {"status": 200, "json": _created_issue_body()}

    connector = _connector(
        {
            ("GET", SEARCH_PATH): _paged_route("issues", created),
            ("POST", CREATE_PATH): _write(
                [],
                status=201,
                body={"id": "10050", "key": "PROJ-7"},
                mutate=lambda _r: created.append({"id": "10050", "key": "PROJ-7"}),
            ),
            ("GET", f"{API}/issue/PROJ-7"): read_back,
        }
    )
    spec = _spec("create_issue")
    plan = asyncio.run(spec.plan(connector, _create_args()))

    outcome = asyncio.run(spec.apply(connector, plan))
    assert outcome.status == "outcome_unknown"
    healthy["value"] = True
    reconciled = asyncio.run(spec.reconcile(connector, plan, outcome))
    assert reconciled.status == "succeeded"
    assert reconciled.result["revision"] == f"10050:{UPDATED}"


# --- update_issue_fields ----------------------------------------------------


def _update_args(expected_updated: str = UPDATED) -> UpdateIssueInput:
    return UpdateIssueInput(
        issue_id_or_key="PROJ-1",
        expected_id="10001",
        expected_updated=expected_updated,
        expected_status="To Do",
        fields={"summary": "Renamed"},
    )


def test_update_issue_fields_puts_fields_and_reconciles() -> None:
    state = _issue_state()
    puts: list[httpx2.Request] = []

    def rename(_request: httpx2.Request) -> None:
        state["summary"] = "Renamed"

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("PUT", ISSUE_ID_PATH): _write(puts, status=204, mutate=rename),
        }
    )
    spec = _spec("update_issue_fields")

    plan = asyncio.run(spec.plan(connector, _update_args()))
    assert plan.request["method"] == "PUT"
    assert plan.request["path"] == ISSUE_ID_PATH
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_issue:10001"
    assert [_body(request) for request in puts] == [{"fields": {"summary": "Renamed"}}]
    assert asyncio.run(spec.reconcile(connector, plan, OUTCOME)).status == "succeeded"


def test_update_issue_fields_reconcile_fails_when_field_not_applied() -> None:
    state = _issue_state()
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
        }
    )
    spec = _spec("update_issue_fields")
    plan = asyncio.run(spec.plan(connector, _update_args()))

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "requested fields are not present"


def test_update_issue_fields_plan_refuses_stale_expected_updated() -> None:
    state = _issue_state()
    connector = _connector({("GET", ISSUE_KEY_PATH): _issue_route(state)})

    with pytest.raises(StalePlan):
        asyncio.run(
            _spec("update_issue_fields").plan(connector, _update_args(expected_updated="2025-01-01T00:00:00.000+0000"))
        )


def test_update_issue_fields_apply_refuses_when_issue_moved_after_plan() -> None:
    state = _issue_state()
    puts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("PUT", ISSUE_ID_PATH): _write(puts, status=204),
        }
    )
    spec = _spec("update_issue_fields")
    plan = asyncio.run(spec.plan(connector, _update_args()))
    state["updated"] = "2026-11-02T08:30:00.000+0000"

    with pytest.raises(StalePlan):
        asyncio.run(spec.apply(connector, plan))
    assert puts == []


# --- add_comment ------------------------------------------------------------


def _add_comment_args() -> AddCommentInput:
    return AddCommentInput(issue_id_or_key="PROJ-1", action_key="act-1", body="hello")


def _marked_comment(comment_id: str = "777") -> dict[str, Any]:
    return {"id": comment_id, "body": _adf(f"hello\n\n{MARKER}"), "updated": COMMENT_UPDATED}


def test_add_comment_posts_adf_body_carrying_action_marker() -> None:
    state = _issue_state()
    comments: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []

    def store(request: httpx2.Request) -> None:
        comments.append({"id": "777", "body": _body(request)["body"], "updated": COMMENT_UPDATED})

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", COMMENT_PATH): _paged_route("comments", comments),
            ("POST", COMMENT_PATH): _write(posts, status=201, body={"id": "777"}, mutate=store),
        }
    )
    spec = _spec("add_comment")

    plan = asyncio.run(spec.plan(connector, _add_comment_args()))
    assert plan.changed is True
    assert plan.request["method"] == "POST"
    assert plan.request["path"] == COMMENT_PATH
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_comment:777"
    sent = _body(posts[0])
    assert sent["body"]["type"] == "doc"
    assert sent["body"]["content"][0]["content"][0]["text"] == f"hello\n\n{MARKER}"


def test_add_comment_replay_is_no_op_and_posts_nothing() -> None:
    state = _issue_state()
    comments = [_marked_comment()]
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", COMMENT_PATH): _paged_route("comments", comments),
            ("POST", COMMENT_PATH): _write(posts, status=201, body={"id": "778"}),
        }
    )
    spec = _spec("add_comment")

    plan = asyncio.run(spec.plan(connector, _add_comment_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert plan.target_ref == "jira_comment:777"
    assert outcome.status == "no_op"
    assert posts == []


def test_add_comment_timeout_after_post_reconciles_to_succeeded() -> None:
    state = _issue_state()
    comments: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []

    def store(request: httpx2.Request) -> None:
        comments.append({"id": "777", "body": _body(request)["body"], "updated": COMMENT_UPDATED})

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", COMMENT_PATH): _paged_route("comments", comments),
            ("POST", COMMENT_PATH): _write(posts, status=201, body={"id": "777"}, mutate=store, timeout=True),
        }
    )
    spec = _spec("add_comment")
    plan = asyncio.run(spec.plan(connector, _add_comment_args()))

    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"
    assert len(posts) == 1

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))
    assert reconciled.status == "succeeded"
    assert reconciled.vendor_ref == "jira_comment:777"


def test_add_comment_timeout_without_written_comment_reconciles_to_failed() -> None:
    state = _issue_state()
    comments: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", COMMENT_PATH): _paged_route("comments", comments),
            ("POST", COMMENT_PATH): _write(posts, status=201, timeout=True),
        }
    )
    spec = _spec("add_comment")
    plan = asyncio.run(spec.plan(connector, _add_comment_args()))

    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"
    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "comment marker not found after write"


# --- update_comment ---------------------------------------------------------


def _update_comment_args(expected_updated: str = COMMENT_UPDATED, body: str = "revised") -> UpdateCommentInput:
    return UpdateCommentInput(issue_id_or_key="10001", comment_id="777", expected_updated=expected_updated, body=body)


def test_update_comment_puts_adf_body_and_reconciles() -> None:
    comment = {"id": "777", "body": _adf("original"), "updated": COMMENT_UPDATED}
    puts: list[httpx2.Request] = []

    def store(request: httpx2.Request) -> None:
        comment["body"] = _body(request)["body"]

    connector = _connector(
        {
            ("GET", COMMENT_ITEM_PATH): _single_or_gone(comment, lambda: True),
            ("PUT", COMMENT_ITEM_PATH): _write(puts, status=200, body={"id": "777"}, mutate=store),
        }
    )
    spec = _spec("update_comment")

    plan = asyncio.run(spec.plan(connector, _update_comment_args()))
    assert plan.changed is True
    assert plan.request["method"] == "PUT"
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_comment:777"
    assert [_body(request) for request in puts] == [{"body": _adf("revised")}]
    assert asyncio.run(spec.reconcile(connector, plan, OUTCOME)).status == "succeeded"


def test_update_comment_is_no_op_when_body_already_matches() -> None:
    comment = {"id": "777", "body": _adf("revised"), "updated": COMMENT_UPDATED}
    puts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", COMMENT_ITEM_PATH): _single_or_gone(comment, lambda: True),
            ("PUT", COMMENT_ITEM_PATH): _write(puts, status=200, body={"id": "777"}),
        }
    )
    spec = _spec("update_comment")

    plan = asyncio.run(spec.plan(connector, _update_comment_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert outcome.status == "no_op"
    assert puts == []


def test_update_comment_plan_refuses_stale_expected_updated() -> None:
    comment = {"id": "777", "body": _adf("original"), "updated": COMMENT_UPDATED}
    connector = _connector({("GET", COMMENT_ITEM_PATH): _single_or_gone(comment, lambda: True)})

    with pytest.raises(StalePlan):
        asyncio.run(
            _spec("update_comment").plan(
                connector, _update_comment_args(expected_updated="2025-01-01T00:00:00.000+0000")
            )
        )


def test_update_comment_reconcile_fails_when_body_was_not_applied() -> None:
    comment = {"id": "777", "body": _adf("original"), "updated": COMMENT_UPDATED}
    connector = _connector({("GET", COMMENT_ITEM_PATH): _single_or_gone(comment, lambda: True)})
    spec = _spec("update_comment")
    plan = asyncio.run(spec.plan(connector, _update_comment_args()))

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "comment body does not match the plan"


# --- transition_issue -------------------------------------------------------


def test_transition_posts_id_of_transition_to_target_status() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []

    def move_to_done(_request: httpx2.Request) -> None:
        state["status"] = "Done"
        state["changelog"] = [{"items": [{"field": "status", "toString": "Done"}]}]

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("GET", TRANSITIONS_PATH): {"status": 200, "json": TRANSITION_LIST},
            ("POST", TRANSITIONS_PATH): _write(posts, status=204, mutate=move_to_done),
        }
    )
    spec = _spec("transition_issue")

    plan = asyncio.run(spec.plan(connector, TransitionIssueInput(issue_id_or_key="PROJ-1", to_status="Done")))
    assert plan.changed is True
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_issue:10001"
    assert [_body(request) for request in posts] == [{"transition": {"id": "31"}}]


def test_transition_plan_rejects_target_without_matching_transition() -> None:
    state = _issue_state()
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", TRANSITIONS_PATH): {"status": 200, "json": TRANSITION_LIST},
        }
    )

    with pytest.raises(ConfigError, match="expected exactly one transition"):
        asyncio.run(
            _spec("transition_issue").plan(
                connector, TransitionIssueInput(issue_id_or_key="PROJ-1", to_status="Archived")
            )
        )


def test_transition_apply_refuses_when_issue_moved_after_plan() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("GET", TRANSITIONS_PATH): {"status": 200, "json": TRANSITION_LIST},
            ("POST", TRANSITIONS_PATH): _write(posts, status=204),
        }
    )
    spec = _spec("transition_issue")
    plan = asyncio.run(spec.plan(connector, TransitionIssueInput(issue_id_or_key="PROJ-1", to_status="Done")))
    state["updated"] = "2026-11-02T08:30:00.000+0000"

    with pytest.raises(StalePlan):
        asyncio.run(spec.apply(connector, plan))
    assert posts == []


def test_transition_is_no_op_when_issue_already_in_target_status() -> None:
    state = _issue_state(status="Done")
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("POST", TRANSITIONS_PATH): _write(posts, status=204),
        }
    )
    spec = _spec("transition_issue")

    plan = asyncio.run(spec.plan(connector, TransitionIssueInput(issue_id_or_key="PROJ-1", to_status="Done")))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert outcome.status == "no_op"
    assert posts == []


def test_transition_timeout_reconciles_through_changelog() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []

    def move_to_done(_request: httpx2.Request) -> None:
        state["status"] = "Done"
        state["changelog"] = [{"items": [{"field": "status", "toString": "Done"}]}]

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("GET", TRANSITIONS_PATH): {"status": 200, "json": TRANSITION_LIST},
            ("POST", TRANSITIONS_PATH): _write(posts, status=204, mutate=move_to_done, timeout=True),
        }
    )
    spec = _spec("transition_issue")
    plan = asyncio.run(spec.plan(connector, TransitionIssueInput(issue_id_or_key="PROJ-1", to_status="Done")))

    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"
    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "succeeded"


def test_transition_reconcile_fails_when_write_never_applied() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("GET", TRANSITIONS_PATH): {"status": 200, "json": TRANSITION_LIST},
            ("POST", TRANSITIONS_PATH): _write(posts, status=204, timeout=True),
        }
    )
    spec = _spec("transition_issue")
    plan = asyncio.run(spec.plan(connector, TransitionIssueInput(issue_id_or_key="PROJ-1", to_status="Done")))
    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "issue is not in the target status"


def test_transition_reconcile_fails_when_status_matches_without_changelog() -> None:
    state = _issue_state()
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("GET", TRANSITIONS_PATH): {"status": 200, "json": TRANSITION_LIST},
        }
    )
    spec = _spec("transition_issue")
    plan = asyncio.run(spec.plan(connector, TransitionIssueInput(issue_id_or_key="PROJ-1", to_status="Done")))
    state["status"] = "Done"

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "status matches but the changelog records no transition to it"


# --- link_issue -------------------------------------------------------------


def _link_args() -> LinkIssueInput:
    return LinkIssueInput(inward_issue="PROJ-1", outward_issue="PROJ-9", link_type="Relates")


def _existing_link() -> dict[str, Any]:
    return {"type": {"name": "Relates"}, "outwardIssue": {"key": "PROJ-9"}}


def test_link_posts_issue_link_and_succeeds() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("POST", LINK_PATH): _write(posts, status=201),
        }
    )
    spec = _spec("link_issue")

    plan = asyncio.run(spec.plan(connector, _link_args()))
    assert plan.changed is True
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == plan.target_ref
    assert [_body(request) for request in posts] == [
        {"type": {"name": "Relates"}, "inwardIssue": {"key": "PROJ-1"}, "outwardIssue": {"key": "PROJ-9"}}
    ]


def test_link_is_no_op_when_link_already_exists() -> None:
    state = _issue_state(issuelinks=[_existing_link()])
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("POST", LINK_PATH): _write(posts, status=201),
        }
    )
    spec = _spec("link_issue")

    plan = asyncio.run(spec.plan(connector, _link_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert outcome.status == "no_op"
    assert posts == []


def test_link_timeout_reconciles_by_rereading_inward_links() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []

    def add_link(_request: httpx2.Request) -> None:
        state["issuelinks"] = [_existing_link()]

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("POST", LINK_PATH): _write(posts, status=201, mutate=add_link, timeout=True),
        }
    )
    spec = _spec("link_issue")
    plan = asyncio.run(spec.plan(connector, _link_args()))

    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"
    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "succeeded"
    assert reconciled.vendor_ref == plan.target_ref


def test_link_reconcile_fails_when_link_never_written() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("POST", LINK_PATH): _write(posts, status=201, timeout=True),
        }
    )
    spec = _spec("link_issue")
    plan = asyncio.run(spec.plan(connector, _link_args()))
    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "issue link not found after write"


# --- add_remote_link --------------------------------------------------------


def _remote_link_args() -> RemoteLinkInput:
    return RemoteLinkInput(
        issue_id_or_key="PROJ-1",
        global_id="system=icuhub&id=finding-1",
        url="https://hooks.example.test/finding-1",
        title="Finding 1",
    )


def _remote_link(link_id: int = 9001) -> dict[str, Any]:
    return {
        "id": link_id,
        "globalId": "system=icuhub&id=finding-1",
        "object": {"url": "https://hooks.example.test/finding-1"},
    }


def test_add_remote_link_posts_object_and_succeeds() -> None:
    state = _issue_state()
    links: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", REMOTE_LINK_PATH): _lists_route(links),
            ("POST", REMOTE_LINK_PATH): _write(
                posts, status=201, body={"id": 9001}, mutate=lambda _r: links.append(_remote_link())
            ),
        }
    )
    spec = _spec("add_remote_link")

    plan = asyncio.run(spec.plan(connector, _remote_link_args()))
    assert plan.changed is True
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_remote_link:9001"
    sent = _body(posts[0])
    assert sent["globalId"] == "system=icuhub&id=finding-1"
    assert sent["object"] == {"url": "https://hooks.example.test/finding-1", "title": "Finding 1"}


def test_add_remote_link_replay_is_no_op_and_posts_nothing() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", REMOTE_LINK_PATH): _lists_route([_remote_link()]),
            ("POST", REMOTE_LINK_PATH): _write(posts, status=201, body={"id": 9002}),
        }
    )
    spec = _spec("add_remote_link")

    plan = asyncio.run(spec.plan(connector, _remote_link_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert plan.target_ref == "jira_remote_link:9001"
    assert outcome.status == "no_op"
    assert posts == []


def test_add_remote_link_timeout_reconciles_by_global_id() -> None:
    state = _issue_state()
    links: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", REMOTE_LINK_PATH): _lists_route(links),
            ("POST", REMOTE_LINK_PATH): _write(
                posts, status=201, mutate=lambda _r: links.append(_remote_link()), timeout=True
            ),
        }
    )
    spec = _spec("add_remote_link")
    plan = asyncio.run(spec.plan(connector, _remote_link_args()))

    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"
    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "succeeded"
    assert reconciled.vendor_ref == plan.target_ref


def test_add_remote_link_reconcile_fails_when_link_never_written() -> None:
    state = _issue_state()
    links: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", REMOTE_LINK_PATH): _lists_route(links),
            ("POST", REMOTE_LINK_PATH): _write(posts, status=201, timeout=True),
        }
    )
    spec = _spec("add_remote_link")
    plan = asyncio.run(spec.plan(connector, _remote_link_args()))
    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "remote link not found after write"


# --- upload_attachment ------------------------------------------------------


def _attachment_args(content: bytes = ATTACHMENT_BYTES) -> AttachmentInput:
    return AttachmentInput(
        issue_id_or_key="PROJ-1",
        filename="evidence.txt",
        media_type="text/plain",
        content_base64=base64.b64encode(content).decode("ascii"),
    )


def _attachment_record() -> dict[str, Any]:
    return {
        "id": "50001",
        "filename": "evidence.txt",
        "size": len(ATTACHMENT_BYTES),
        "created": ATTACHMENT_CREATED,
    }


def test_upload_attachment_posts_multipart_and_succeeds() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []

    def store(_request: httpx2.Request) -> None:
        state["attachment"] = [_attachment_record()]

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("POST", ATTACHMENTS_PATH): _write(posts, status=200, body=[_attachment_record()], mutate=store),
        }
    )
    spec = _spec("upload_attachment")

    plan = asyncio.run(spec.plan(connector, _attachment_args()))
    assert plan.changed is True
    assert plan.diff["size"] == len(ATTACHMENT_BYTES)
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_attachment:50001"
    assert ATTACHMENT_BYTES in posts[0].content
    assert b"evidence.txt" in posts[0].content


def test_upload_attachment_replay_is_no_op_and_posts_nothing() -> None:
    state = _issue_state(attachment=[_attachment_record()])
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("POST", ATTACHMENTS_PATH): _write(posts, status=200, body=[_attachment_record()]),
        }
    )
    spec = _spec("upload_attachment")

    plan = asyncio.run(spec.plan(connector, _attachment_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert plan.target_ref == "jira_attachment:50001"
    assert outcome.status == "no_op"
    assert posts == []


def test_upload_attachment_rejects_content_over_attachment_max_bytes() -> None:
    state = _issue_state()
    connector = _connector({("GET", ISSUE_KEY_PATH): _issue_route(state)}, attachment_max_bytes=8)

    with pytest.raises(ConfigError, match="attachment_max_bytes"):
        asyncio.run(_spec("upload_attachment").plan(connector, _attachment_args()))


def test_upload_attachment_timeout_reconciles_by_filename_and_size() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []

    def store(_request: httpx2.Request) -> None:
        state["attachment"] = [_attachment_record()]

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("POST", ATTACHMENTS_PATH): _write(
                posts, status=200, body=[_attachment_record()], mutate=store, timeout=True
            ),
        }
    )
    spec = _spec("upload_attachment")
    plan = asyncio.run(spec.plan(connector, _attachment_args()))

    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"
    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "succeeded"
    assert reconciled.vendor_ref == "jira_attachment:50001"


def test_upload_attachment_reconcile_fails_when_attachment_never_written() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("POST", ATTACHMENTS_PATH): _write(posts, status=200, timeout=True),
        }
    )
    spec = _spec("upload_attachment")
    plan = asyncio.run(spec.plan(connector, _attachment_args()))
    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "attachment not found after write"


# --- create_webhook / delete_webhook / refresh_webhook ----------------------


def _registration(webhook_id: int = 4001, url: str = WEBHOOK_URL) -> dict[str, Any]:
    return {
        "id": webhook_id,
        "url": url,
        "events": [WEBHOOK_EVENT],
        "expirationDate": "2026-12-01T00:00:00.000+0000",
    }


def _create_webhook_args() -> CreateWebhookInput:
    return CreateWebhookInput(name="icuhub", url=WEBHOOK_URL, events=[WEBHOOK_EVENT], jql_filter="project = PROJ")


EXTENDED_EXPIRY = "2027-01-01T00:00:00.000+0000"


def _extend_expiry(registrations: list[dict[str, Any]]) -> Callable[[httpx2.Request], None]:
    def extend(_request: httpx2.Request) -> None:
        for raw in registrations:
            raw["expirationDate"] = EXTENDED_EXPIRY

    return extend


def test_create_webhook_posts_registration_and_succeeds() -> None:
    registrations: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", registrations),
            ("POST", WEBHOOK_PATH): _write(
                posts,
                status=201,
                body={"webhookRegistrationResult": [{"createdWebhookId": 4001}]},
                mutate=lambda _r: registrations.append(_registration()),
            ),
        }
    )
    spec = _spec("create_webhook")

    plan = asyncio.run(spec.plan(connector, _create_webhook_args()))
    assert plan.changed is True
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_webhook:4001"
    assert _body(posts[0]) == {
        "url": WEBHOOK_URL,
        "webhooks": [{"events": [WEBHOOK_EVENT], "jqlFilter": "project = PROJ"}],
    }


def test_create_webhook_replay_is_no_op_and_posts_nothing() -> None:
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", [_registration()]),
            ("POST", WEBHOOK_PATH): _write(
                posts, status=201, body={"webhookRegistrationResult": [{"createdWebhookId": 4002}]}
            ),
        }
    )
    spec = _spec("create_webhook")

    plan = asyncio.run(spec.plan(connector, _create_webhook_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert plan.target_ref == "jira_webhook:4001"
    assert outcome.status == "no_op"
    assert posts == []


def test_create_webhook_reports_vendor_registration_error_as_failed() -> None:
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", []),
            ("POST", WEBHOOK_PATH): _write(
                posts,
                status=201,
                body={"webhookRegistrationResult": [{"errors": {"url": "not reachable"}}]},
            ),
        }
    )
    spec = _spec("create_webhook")
    plan = asyncio.run(spec.plan(connector, _create_webhook_args()))

    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "failed"
    assert outcome.error is not None
    assert outcome.error.startswith("Jira webhook registration failed")


def test_create_webhook_timeout_reconciles_by_url() -> None:
    registrations: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", registrations),
            ("POST", WEBHOOK_PATH): _write(
                posts,
                status=201,
                body={"webhookRegistrationResult": [{"createdWebhookId": 4001}]},
                mutate=lambda _r: registrations.append(_registration()),
                timeout=True,
            ),
        }
    )
    spec = _spec("create_webhook")
    plan = asyncio.run(spec.plan(connector, _create_webhook_args()))

    assert asyncio.run(spec.apply(connector, plan)).status == "outcome_unknown"
    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "succeeded"
    assert reconciled.vendor_ref == "jira_webhook:4001"
    assert reconciled.result is not None
    assert reconciled.result["expiration_date"] == "2026-12-01T00:00:00.000+0000"


def test_create_webhook_reconcile_fails_when_never_registered() -> None:
    connector = _connector({("GET", WEBHOOK_PATH): _paged_route("values", [])})
    spec = _spec("create_webhook")
    plan = asyncio.run(spec.plan(connector, _create_webhook_args()))

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"


def test_delete_webhook_deletes_registration_and_reconciles_absent() -> None:
    registrations = [_registration()]
    deletes: list[httpx2.Request] = []

    def remove(_request: httpx2.Request) -> None:
        registrations.clear()

    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", registrations),
            ("DELETE", WEBHOOK_PATH): _write(deletes, status=204, mutate=remove),
        },
        destructive_enabled=True,
    )
    spec = _spec("delete_webhook")
    args = DeleteWebhookInput(webhook_id="4001", expected_url=WEBHOOK_URL)

    plan = asyncio.run(spec.plan(connector, args))
    assert plan.changed is True
    assert plan.request["json"] == {"webhookIds": [4001]}
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_webhook:4001"
    assert _body(deletes[0]) == {"webhookIds": [4001]}
    assert asyncio.run(spec.reconcile(connector, plan, OUTCOME)).status == "succeeded"


def test_delete_webhook_is_no_op_when_registration_already_gone() -> None:
    deletes: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", []),
            ("DELETE", WEBHOOK_PATH): _write(deletes, status=204),
        },
        destructive_enabled=True,
    )
    spec = _spec("delete_webhook")

    plan = asyncio.run(spec.plan(connector, DeleteWebhookInput(webhook_id="4001", expected_url=WEBHOOK_URL)))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert outcome.status == "no_op"
    assert deletes == []


def test_delete_webhook_plan_refuses_changed_url() -> None:
    connector = _connector(
        {("GET", WEBHOOK_PATH): _paged_route("values", [_registration(url="https://hooks.example.test/moved")])},
        destructive_enabled=True,
    )

    with pytest.raises(StalePlan):
        asyncio.run(
            _spec("delete_webhook").plan(connector, DeleteWebhookInput(webhook_id="4001", expected_url=WEBHOOK_URL))
        )


def test_delete_webhook_reconcile_fails_while_still_registered() -> None:
    registrations = [_registration()]
    connector = _connector(
        {("GET", WEBHOOK_PATH): _paged_route("values", registrations)},
        destructive_enabled=True,
    )
    spec = _spec("delete_webhook")
    plan = asyncio.run(spec.plan(connector, DeleteWebhookInput(webhook_id="4001", expected_url=WEBHOOK_URL)))

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "webhook still registered"


def test_refresh_webhook_puts_ids_and_reconciles_registered() -> None:
    registrations = [_registration()]
    puts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", registrations),
            ("PUT", WEBHOOK_REFRESH_PATH): _write(puts, status=202, mutate=_extend_expiry(registrations)),
        }
    )
    spec = _spec("refresh_webhook")

    plan = asyncio.run(spec.plan(connector, RefreshWebhookInput(webhook_ids=["4001"])))
    assert plan.changed is True
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_webhook:4001"
    assert _body(puts[0]) == {"webhookIds": [4001]}
    assert asyncio.run(spec.reconcile(connector, plan, OUTCOME)).status == "succeeded"


def test_refresh_webhook_plan_refuses_missing_registration() -> None:
    connector = _connector({("GET", WEBHOOK_PATH): _paged_route("values", [])})

    with pytest.raises(StalePlan, match="no longer exist"):
        asyncio.run(_spec("refresh_webhook").plan(connector, RefreshWebhookInput(webhook_ids=["4001"])))


def test_refresh_webhook_reconcile_reports_expired_registration() -> None:
    registrations = [_registration()]
    connector = _connector({("GET", WEBHOOK_PATH): _paged_route("values", registrations)})
    spec = _spec("refresh_webhook")
    plan = asyncio.run(spec.plan(connector, RefreshWebhookInput(webhook_ids=["4001"])))
    registrations.clear()

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "registrations absent from the read-back: 4001; re-create them"


def test_refresh_webhook_apply_is_unverified_when_expiry_not_advanced() -> None:
    registrations = [_registration()]
    puts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", registrations),
            ("PUT", WEBHOOK_REFRESH_PATH): _write(puts, status=202),
        }
    )
    spec = _spec("refresh_webhook")
    plan = asyncio.run(spec.plan(connector, RefreshWebhookInput(webhook_ids=["4001"])))

    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "unverified"
    assert outcome.error == "expiry not verifiably extended in the read-back: 4001"


def test_refresh_webhook_apply_fails_when_registration_disappears() -> None:
    registrations = [_registration()]
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", registrations),
            ("PUT", WEBHOOK_REFRESH_PATH): _write(
                [], status=202, mutate=lambda _r: registrations.clear()
            ),
        }
    )
    spec = _spec("refresh_webhook")
    plan = asyncio.run(spec.plan(connector, RefreshWebhookInput(webhook_ids=["4001"])))

    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "failed"
    assert outcome.error == "registrations absent from the read-back: 4001; re-create them"


def test_create_webhook_apply_fails_when_created_id_absent_from_read_back() -> None:
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", []),
            ("POST", WEBHOOK_PATH): _write(
                posts, status=201, body={"webhookRegistrationResult": [{"createdWebhookId": 4001}]}
            ),
        }
    )
    spec = _spec("create_webhook")
    plan = asyncio.run(spec.plan(connector, _create_webhook_args()))

    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "failed"
    assert outcome.error == "created webhook is absent from the registration read-back"


def test_create_webhook_apply_fails_when_read_back_url_differs() -> None:
    registrations: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", registrations),
            ("POST", WEBHOOK_PATH): _write(
                posts,
                status=201,
                body={"webhookRegistrationResult": [{"createdWebhookId": 4001}]},
                mutate=lambda _r: registrations.append(_registration(url="https://hooks.example.test/moved")),
            ),
        }
    )
    spec = _spec("create_webhook")
    plan = asyncio.run(spec.plan(connector, _create_webhook_args()))

    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "failed"
    assert outcome.error == "created webhook URL differs from the approved URL"


def test_create_webhook_apply_is_unverified_when_read_back_omits_url() -> None:
    registrations: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    omitted = _registration()
    del omitted["url"]
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", registrations),
            ("POST", WEBHOOK_PATH): _write(
                posts,
                status=201,
                body={"webhookRegistrationResult": [{"createdWebhookId": 4001}]},
                mutate=lambda _r: registrations.append(omitted),
            ),
        }
    )
    spec = _spec("create_webhook")
    plan = asyncio.run(spec.plan(connector, _create_webhook_args()))

    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "unverified"
    assert outcome.error == "registration read-back omitted the webhook URL"


def test_create_webhook_reconcile_is_unverified_when_read_back_omits_urls() -> None:
    omitted = _registration()
    del omitted["url"]
    connector = _connector({("GET", WEBHOOK_PATH): _paged_route("values", [omitted])})
    spec = _spec("create_webhook")
    plan = asyncio.run(spec.plan(connector, _create_webhook_args()))

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "unverified"


def test_delete_webhook_apply_fails_when_registration_survives_delete() -> None:
    registrations = [_registration()]
    deletes: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", WEBHOOK_PATH): _paged_route("values", registrations),
            ("DELETE", WEBHOOK_PATH): _write(deletes, status=204),
        },
        destructive_enabled=True,
    )
    spec = _spec("delete_webhook")
    plan = asyncio.run(spec.plan(connector, DeleteWebhookInput(webhook_id="4001", expected_url=WEBHOOK_URL)))

    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "failed"
    assert outcome.error == "webhook still registered"


# --- destructive deletes ----------------------------------------------------


def test_delete_issue_deletes_issue_and_reconciles_absent() -> None:
    state = _issue_state()
    deletes: list[httpx2.Request] = []

    def remove(_request: httpx2.Request) -> None:
        state["deleted"] = True

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_or_gone(state),
            ("DELETE", ISSUE_ID_PATH): _write(deletes, status=204, mutate=remove),
        },
        destructive_enabled=True,
    )
    spec = _spec("delete_issue")
    args = DeleteIssueInput(issue_id_or_key="PROJ-1", expected_id="10001")

    plan = asyncio.run(spec.plan(connector, args))
    assert plan.request["params"] == {"deleteSubtasks": "false"}
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_issue:10001"
    assert len(deletes) == 1
    assert asyncio.run(spec.reconcile(connector, plan, OUTCOME)).status == "succeeded"


def test_delete_issue_plan_refuses_mismatched_expected_id() -> None:
    state = _issue_state()
    connector = _connector({("GET", ISSUE_KEY_PATH): _issue_route(state)}, destructive_enabled=True)

    with pytest.raises(StalePlan):
        asyncio.run(
            _spec("delete_issue").plan(connector, DeleteIssueInput(issue_id_or_key="PROJ-1", expected_id="99999"))
        )


def test_delete_issue_reconcile_fails_while_issue_still_exists() -> None:
    state = _issue_state()
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_or_gone(state),
        },
        destructive_enabled=True,
    )
    spec = _spec("delete_issue")
    plan = asyncio.run(spec.plan(connector, DeleteIssueInput(issue_id_or_key="PROJ-1", expected_id="10001")))

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "issue still exists after delete"


def test_delete_comment_deletes_comment_and_reconciles_absent() -> None:
    comments = [{"id": "777", "body": _adf("original"), "updated": COMMENT_UPDATED}]
    deletes: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", COMMENT_ITEM_PATH): _single_or_gone(comments[0], lambda: bool(comments)),
            ("DELETE", COMMENT_ITEM_PATH): _write(deletes, status=204, mutate=lambda _r: comments.clear()),
        },
        destructive_enabled=True,
    )
    spec = _spec("delete_comment")
    args = DeleteCommentInput(issue_id_or_key="10001", comment_id="777", expected_updated=COMMENT_UPDATED)

    plan = asyncio.run(spec.plan(connector, args))
    assert plan.request["path"] == COMMENT_ITEM_PATH
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_comment:777"
    assert len(deletes) == 1
    assert asyncio.run(spec.reconcile(connector, plan, OUTCOME)).status == "succeeded"


def test_delete_comment_plan_refuses_changed_comment() -> None:
    comment = {"id": "777", "body": _adf("original"), "updated": "2026-11-09T09:00:00.000+0000"}
    connector = _connector(
        {("GET", COMMENT_ITEM_PATH): _single_or_gone(comment, lambda: True)},
        destructive_enabled=True,
    )

    with pytest.raises(StalePlan):
        asyncio.run(
            _spec("delete_comment").plan(
                connector,
                DeleteCommentInput(issue_id_or_key="10001", comment_id="777", expected_updated=COMMENT_UPDATED),
            )
        )


def test_delete_comment_reconcile_fails_while_comment_still_exists() -> None:
    comment = {"id": "777", "body": _adf("original"), "updated": COMMENT_UPDATED}
    connector = _connector(
        {("GET", COMMENT_ITEM_PATH): _single_or_gone(comment, lambda: True)},
        destructive_enabled=True,
    )
    spec = _spec("delete_comment")
    plan = asyncio.run(
        spec.plan(
            connector, DeleteCommentInput(issue_id_or_key="10001", comment_id="777", expected_updated=COMMENT_UPDATED)
        )
    )

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "comment still exists after delete"


def test_delete_attachment_deletes_attachment_and_reconciles_absent() -> None:
    attachments = [_attachment_record()]
    deletes: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ATTACHMENT_PATH): _single_or_gone(attachments[0], lambda: bool(attachments)),
            ("DELETE", ATTACHMENT_PATH): _write(deletes, status=204, mutate=lambda _r: attachments.clear()),
        },
        destructive_enabled=True,
    )
    spec = _spec("delete_attachment")
    args = DeleteAttachmentInput(attachment_id="50001", expected_created=ATTACHMENT_CREATED)

    plan = asyncio.run(spec.plan(connector, args))
    assert plan.diff == {"filename": "evidence.txt"}
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_attachment:50001"
    assert len(deletes) == 1
    assert asyncio.run(spec.reconcile(connector, plan, OUTCOME)).status == "succeeded"


def test_delete_attachment_plan_refuses_changed_attachment() -> None:
    record = {**_attachment_record(), "created": "2026-11-09T09:00:00.000+0000"}
    connector = _connector(
        {("GET", ATTACHMENT_PATH): _single_or_gone(record, lambda: True)},
        destructive_enabled=True,
    )

    with pytest.raises(StalePlan):
        asyncio.run(
            _spec("delete_attachment").plan(
                connector, DeleteAttachmentInput(attachment_id="50001", expected_created=ATTACHMENT_CREATED)
            )
        )


def test_delete_attachment_reconcile_fails_while_attachment_still_exists() -> None:
    record = _attachment_record()
    connector = _connector(
        {("GET", ATTACHMENT_PATH): _single_or_gone(record, lambda: True)},
        destructive_enabled=True,
    )
    spec = _spec("delete_attachment")
    plan = asyncio.run(
        spec.plan(connector, DeleteAttachmentInput(attachment_id="50001", expected_created=ATTACHMENT_CREATED))
    )

    reconciled = asyncio.run(spec.reconcile(connector, plan, OUTCOME))

    assert reconciled.status == "failed"
    assert reconciled.error == "attachment still exists after delete"


@pytest.mark.parametrize(
    ("action", "args"),
    [
        ("delete_issue", DeleteIssueInput(issue_id_or_key="PROJ-1", expected_id="10001")),
        (
            "delete_comment",
            DeleteCommentInput(issue_id_or_key="10001", comment_id="777", expected_updated=COMMENT_UPDATED),
        ),
        ("delete_attachment", DeleteAttachmentInput(attachment_id="50001", expected_created=ATTACHMENT_CREATED)),
        ("delete_webhook", DeleteWebhookInput(webhook_id="4001", expected_url=WEBHOOK_URL)),
    ],
)
def test_destructive_plans_are_blocked_when_destructive_writes_are_disabled(action: str, args: Any) -> None:
    connector = _connector({})

    with pytest.raises(ConfigError, match="destructive_enabled is false"):
        asyncio.run(_spec(action).plan(connector, args))
