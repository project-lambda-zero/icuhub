"""Action conformance for the Jira Data Center write paths, run through recorded transports.

Covers ``add_comment``, ``transition_issue``, ``link_issue``, ``update_issue_fields``,
``add_attachment``, and ``delete_issue``: plan, apply, no-op replay where supported, stale-plan
preconditions, ``outcome_unknown`` after a transport timeout on a non-idempotent write, and
reconcile. A read-only transport guard proves the required plans send no writes. Requests are
answered by ``RouteTransport``. Route callables mutate synthetic issue, comment, and attachment
state so reconcile observes the write.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any, cast

import httpx2
import pytest

from icuhub.connectors._jira.models import AddCommentInput, LinkIssueInput, TransitionIssueInput, UpdateIssueInput
from icuhub.connectors.jira_dc import JiraDataCenter
from icuhub.kit.errors import ConfigError, StalePlan
from icuhub.kit.testing import RouteTransport, make_connector
from icuhub.kit.types import ActionOutcome

BASE = "https://jira.example.test"
PAT_REF = "jira-pat"
SECRETS = {PAT_REF: b"synthetic-pat"}

ISSUE_KEY_PATH = "/rest/api/2/issue/PROJ-1"
ISSUE_ID_PATH = "/rest/api/2/issue/10001"
COMMENT_PATH = "/rest/api/2/issue/10001/comment"
TRANSITIONS_PATH = "/rest/api/2/issue/10001/transitions"
LINK_PATH = "/rest/api/2/issueLink"
TRANSITION_LIST = {
    "transitions": [
        {"id": "21", "to": {"name": "In Progress"}},
        {"id": "31", "to": {"name": "Done"}},
    ]
}
MARKER = "[icuhub-action:act-1]"


def _connector(routes: dict[tuple[str, str], Any]) -> JiraDataCenter:
    config = {"base_url": BASE, "personal_access_token": {"ref": PAT_REF}}
    return cast(JiraDataCenter, make_connector(JiraDataCenter, config, RouteTransport(routes), SECRETS))


def _spec(name: str) -> Any:
    return JiraDataCenter.actions()[name]


def _body(request: httpx2.Request) -> Any:
    return json.loads(request.content)


def _issue_state(**overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "id": "10001",
        "key": "PROJ-1",
        "status": "To Do",
        "updated": "2026-11-01T10:00:00.000+0000",
        "summary": "Original",
        "issuelinks": [],
        "changelog": [],
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
        },
        "changelog": {"histories": list(state["changelog"])},
    }


def _issue_route(state: dict[str, Any]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(_request: httpx2.Request) -> dict[str, Any]:
        return {"status": 200, "json": _issue_body(state)}

    return handler


def _comments_route(comments: list[dict[str, Any]]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(_request: httpx2.Request) -> dict[str, Any]:
        return {"status": 200, "json": {"startAt": 0, "maxResults": 50, "total": len(comments), "comments": list(comments)}}

    return handler


def _post_comment(
    comments: list[dict[str, Any]], posts: list[httpx2.Request], *, timeout: bool
) -> Callable[[httpx2.Request], Any]:
    def handler(request: httpx2.Request) -> Any:
        posts.append(request)
        comments.append({"id": "777", "body": _body(request)["body"]})
        if timeout:
            raise httpx2.ReadTimeout("synthetic read timeout after comment write")
        return {"status": 201, "json": {"id": "777", "body": _body(request)["body"]}}

    return handler


def _lost_post(posts: list[httpx2.Request]) -> Callable[[httpx2.Request], Any]:
    def handler(request: httpx2.Request) -> Any:
        posts.append(request)
        raise httpx2.ReadTimeout("synthetic read timeout, write never applied")

    return handler


def _recording_post(
    posts: list[httpx2.Request], *, status: int, mutate: Callable[[], None] | None = None, timeout: bool = False
) -> Callable[[httpx2.Request], Any]:
    def handler(request: httpx2.Request) -> Any:
        posts.append(request)
        if mutate is not None:
            mutate()
        if timeout:
            raise httpx2.ReadTimeout("synthetic read timeout after write")
        return httpx2.Response(status)

    return handler


def _add_comment_args() -> AddCommentInput:
    return AddCommentInput(issue_id_or_key="PROJ-1", action_key="act-1", body="hello")


# --- add_comment ------------------------------------------------------------


def test_add_comment_posts_body_carrying_action_marker() -> None:
    state = _issue_state()
    comments: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", COMMENT_PATH): _comments_route(comments),
            ("POST", COMMENT_PATH): _post_comment(comments, posts, timeout=False),
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
    assert [_body(request) for request in posts] == [{"body": f"hello\n\n{MARKER}"}]


def test_add_comment_replay_is_no_op_and_posts_nothing() -> None:
    state = _issue_state()
    comments = [{"id": "777", "body": f"hello\n\n{MARKER}"}]
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", COMMENT_PATH): _comments_route(comments),
            ("POST", COMMENT_PATH): _post_comment(comments, posts, timeout=False),
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
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", COMMENT_PATH): _comments_route(comments),
            ("POST", COMMENT_PATH): _post_comment(comments, posts, timeout=True),
        }
    )
    spec = _spec("add_comment")
    plan = asyncio.run(spec.plan(connector, _add_comment_args()))

    outcome = asyncio.run(spec.apply(connector, plan))
    assert outcome.status == "outcome_unknown"
    assert len(posts) == 1

    reconciled = asyncio.run(spec.reconcile(connector, plan, outcome))
    assert reconciled.status == "succeeded"
    assert reconciled.vendor_ref == "jira_comment:777"


def test_add_comment_timeout_without_written_comment_reconciles_to_failed() -> None:
    state = _issue_state()
    comments: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", COMMENT_PATH): _comments_route(comments),
            ("POST", COMMENT_PATH): _lost_post(posts),
        }
    )
    spec = _spec("add_comment")
    plan = asyncio.run(spec.plan(connector, _add_comment_args()))

    outcome = asyncio.run(spec.apply(connector, plan))
    assert outcome.status == "outcome_unknown"

    reconciled = asyncio.run(spec.reconcile(connector, plan, outcome))
    assert reconciled.status == "failed"
    assert reconciled.error == "comment marker not found after write"


# --- transition_issue -------------------------------------------------------


def test_transition_posts_id_of_transition_to_target_status() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []

    def move_to_done() -> None:
        state["status"] = "Done"
        state["changelog"] = [{"items": [{"field": "status", "toString": "Done"}]}]

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("GET", TRANSITIONS_PATH): {"status": 200, "json": TRANSITION_LIST},
            ("POST", TRANSITIONS_PATH): _recording_post(posts, status=204, mutate=move_to_done),
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
            _spec("transition_issue").plan(connector, TransitionIssueInput(issue_id_or_key="PROJ-1", to_status="Archived"))
        )


def test_transition_apply_refuses_when_issue_moved_after_plan() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("GET", TRANSITIONS_PATH): {"status": 200, "json": TRANSITION_LIST},
            ("POST", TRANSITIONS_PATH): _recording_post(posts, status=204),
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
            ("POST", TRANSITIONS_PATH): _recording_post(posts, status=204),
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

    def move_to_done() -> None:
        state["status"] = "Done"
        state["changelog"] = [{"items": [{"field": "status", "toString": "Done"}]}]

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("GET", TRANSITIONS_PATH): {"status": 200, "json": TRANSITION_LIST},
            ("POST", TRANSITIONS_PATH): _recording_post(posts, status=204, mutate=move_to_done, timeout=True),
        }
    )
    spec = _spec("transition_issue")
    plan = asyncio.run(spec.plan(connector, TransitionIssueInput(issue_id_or_key="PROJ-1", to_status="Done")))

    outcome = asyncio.run(spec.apply(connector, plan))
    assert outcome.status == "outcome_unknown"

    reconciled = asyncio.run(spec.reconcile(connector, plan, outcome))
    assert reconciled.status == "succeeded"


def test_transition_reconcile_fails_when_write_never_applied() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("GET", TRANSITIONS_PATH): {"status": 200, "json": TRANSITION_LIST},
            ("POST", TRANSITIONS_PATH): _recording_post(posts, status=204, timeout=True),
        }
    )
    spec = _spec("transition_issue")
    plan = asyncio.run(spec.plan(connector, TransitionIssueInput(issue_id_or_key="PROJ-1", to_status="Done")))
    outcome = asyncio.run(spec.apply(connector, plan))
    assert outcome.status == "outcome_unknown"

    reconciled = asyncio.run(spec.reconcile(connector, plan, outcome))

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

    prior = ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)
    reconciled = asyncio.run(spec.reconcile(connector, plan, prior))

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
            ("POST", LINK_PATH): _recording_post(posts, status=201),
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
            ("POST", LINK_PATH): _recording_post(posts, status=201),
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

    def add_link() -> None:
        state["issuelinks"] = [_existing_link()]

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("POST", LINK_PATH): _recording_post(posts, status=201, mutate=add_link, timeout=True),
        }
    )
    spec = _spec("link_issue")
    plan = asyncio.run(spec.plan(connector, _link_args()))

    outcome = asyncio.run(spec.apply(connector, plan))
    assert outcome.status == "outcome_unknown"
    reconciled = asyncio.run(spec.reconcile(connector, plan, outcome))

    assert reconciled.status == "succeeded"
    assert reconciled.vendor_ref == plan.target_ref


def test_link_reconcile_fails_when_link_never_written() -> None:
    state = _issue_state()
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("POST", LINK_PATH): _recording_post(posts, status=201, timeout=True),
        }
    )
    spec = _spec("link_issue")
    plan = asyncio.run(spec.plan(connector, _link_args()))
    outcome = asyncio.run(spec.apply(connector, plan))
    assert outcome.status == "outcome_unknown"

    reconciled = asyncio.run(spec.reconcile(connector, plan, outcome))

    assert reconciled.status == "failed"
    assert reconciled.error == "link not present after write"


# --- update_issue_fields ----------------------------------------------------


def _update_args(expected_updated: str = "2026-11-01T10:00:00.000+0000") -> UpdateIssueInput:
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

    def rename() -> None:
        state["summary"] = "Renamed"

    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("PUT", ISSUE_ID_PATH): _recording_post(puts, status=204, mutate=rename),
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
    assert asyncio.run(spec.reconcile(connector, plan, outcome)).status == "succeeded"


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

    prior = ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)
    reconciled = asyncio.run(spec.reconcile(connector, plan, prior))

    assert reconciled.status == "failed"
    assert reconciled.error == "requested field values do not match the plan"


def test_update_issue_fields_plan_refuses_stale_expected_updated() -> None:
    state = _issue_state()
    connector = _connector({("GET", ISSUE_KEY_PATH): _issue_route(state)})

    with pytest.raises(StalePlan):
        asyncio.run(_spec("update_issue_fields").plan(connector, _update_args(expected_updated="2025-01-01T00:00:00.000+0000")))


def test_update_issue_fields_apply_refuses_when_issue_moved_after_plan() -> None:
    state = _issue_state()
    puts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(state),
            ("GET", ISSUE_ID_PATH): _issue_route(state),
            ("PUT", ISSUE_ID_PATH): _recording_post(puts, status=204),
        }
    )
    spec = _spec("update_issue_fields")
    plan = asyncio.run(spec.plan(connector, _update_args()))
    state["updated"] = "2026-11-02T08:30:00.000+0000"

    with pytest.raises(StalePlan):
        asyncio.run(spec.apply(connector, plan))
    assert puts == []
