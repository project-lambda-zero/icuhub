"""Tests for the Jira Data Center comment update, remote link, and read operations.

Covers ``update_comment`` and ``add_remote_link`` (plan, apply, no-op replay, stale-revision
refusal, reconcile) plus ``list_comments``, ``list_remote_links``, ``get_edit_metadata``,
``list_fields``, and ``list_projects``. Requests are answered by ``RouteTransport``; route
callables mutate synthetic comment and remote-link state so reconcile observes each write.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any, cast

import httpx2
import pydantic
import pytest

from icuhub.connectors.jira_dc import JiraDataCenter
from icuhub.connectors.jira_dc.comments_links import (
    AddRemoteLinkArgs,
    GetEditMetadataArgs,
    ListCommentsArgs,
    ListFieldsArgs,
    ListProjectsArgs,
    ListRemoteLinksArgs,
    UpdateCommentArgs,
)
from icuhub.kit.errors import StalePlan
from icuhub.kit.testing import RouteTransport, make_connector

BASE = "https://jira.example.test"
PAT_REF = "jira-pat"
SECRETS = {PAT_REF: b"synthetic-pat"}

ISSUE_KEY_PATH = "/rest/api/2/issue/PROJ-1"
COMMENT_LIST_PATH = "/rest/api/2/issue/10001/comment"
COMMENT_PATH = "/rest/api/2/issue/10001/comment/555"
REMOTE_LINK_PATH = "/rest/api/2/issue/10001/remotelink"
EDIT_META_PATH = "/rest/api/2/issue/10001/editmeta"
FIELD_PATH = "/rest/api/2/field"
PROJECT_PATH = "/rest/api/2/project"

UPDATED_OLD = "2026-11-01T10:00:00.000+0000"
UPDATED_NEW = "2026-11-02T08:30:00.000+0000"
GLOBAL_ID = "system=https://tracker.example.test&id=42"
URL = "https://tracker.example.test/items/42"


def _connector(routes: dict[tuple[str, str], Any]) -> JiraDataCenter:
    config = {"base_url": BASE, "personal_access_token": {"ref": PAT_REF}}
    return cast(JiraDataCenter, make_connector(JiraDataCenter, config, RouteTransport(routes), SECRETS))


def _spec(name: str) -> Any:
    return JiraDataCenter.actions()[name]


def _op(name: str) -> Any:
    return JiraDataCenter.operations()[name]


def _body(request: httpx2.Request) -> Any:
    return json.loads(request.content)


def _issue_route(issue_id: str = "10001") -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(_request: httpx2.Request) -> dict[str, Any]:
        return {"status": 200, "json": {"id": issue_id, "key": "PROJ-1"}}

    return handler


def _comment_state(body: str = "Original", updated: str = UPDATED_OLD) -> dict[str, Any]:
    return {"id": "555", "body": body, "updated": updated}


def _comment_route(state: dict[str, Any]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(_request: httpx2.Request) -> dict[str, Any]:
        return {"status": 200, "json": dict(state)}

    return handler


def _recording_put(
    puts: list[httpx2.Request], state: dict[str, Any]
) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(request: httpx2.Request) -> dict[str, Any]:
        puts.append(request)
        state["body"] = _body(request)["body"]
        state["updated"] = UPDATED_NEW
        return {"status": 200, "json": dict(state)}

    return handler


def _update_args(**overrides: Any) -> UpdateCommentArgs:
    values: dict[str, Any] = {
        "issue_id_or_key": "10001",
        "comment_id": "555",
        "expected_updated": UPDATED_OLD,
        "body": "Revised",
    }
    values.update(overrides)
    return UpdateCommentArgs(**values)


def _link_args(**overrides: Any) -> AddRemoteLinkArgs:
    values: dict[str, Any] = {"issue_id_or_key": "PROJ-1", "global_id": GLOBAL_ID, "url": URL, "title": "Item 42"}
    values.update(overrides)
    return AddRemoteLinkArgs(**values)


def _links_route(links: list[dict[str, Any]]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(_request: httpx2.Request) -> dict[str, Any]:
        return {"status": 200, "json": list(links)}

    return handler


def _recording_link_post(
    posts: list[httpx2.Request], links: list[dict[str, Any]]
) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(request: httpx2.Request) -> dict[str, Any]:
        posts.append(request)
        payload = _body(request)
        link = {"id": 9001, "globalId": payload["globalId"], "object": payload["object"]}
        links.append(link)
        return {"status": 201, "json": link}

    return handler


def test_update_comment_plan_is_noop_when_body_already_matches() -> None:
    connector = _connector({("GET", COMMENT_PATH): _comment_route(_comment_state("Revised"))})
    spec = _spec("update_comment")

    plan = asyncio.run(spec.plan(connector, _update_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert plan.target_ref == "jira_comment:555"
    assert outcome.status == "no_op"


def test_update_comment_plan_refuses_stale_revision() -> None:
    connector = _connector({("GET", COMMENT_PATH): _comment_route(_comment_state(updated=UPDATED_NEW))})

    with pytest.raises(StalePlan):
        asyncio.run(_spec("update_comment").plan(connector, _update_args()))


def test_update_comment_apply_puts_plain_body_exactly() -> None:
    state = _comment_state()
    puts: list[httpx2.Request] = []
    connector = _connector({("GET", COMMENT_PATH): _comment_route(state), ("PUT", COMMENT_PATH): _recording_put(puts, state)})
    spec = _spec("update_comment")

    plan = asyncio.run(spec.plan(connector, _update_args()))
    assert plan.changed is True
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_comment:555"
    assert [_body(request) for request in puts] == [{"body": "Revised"}]
    assert asyncio.run(spec.reconcile(connector, plan)).status == "succeeded"


def test_update_comment_apply_refuses_when_comment_moved_after_plan() -> None:
    state = _comment_state()
    puts: list[httpx2.Request] = []
    connector = _connector({("GET", COMMENT_PATH): _comment_route(state), ("PUT", COMMENT_PATH): _recording_put(puts, state)})
    spec = _spec("update_comment")
    plan = asyncio.run(spec.plan(connector, _update_args()))
    state["updated"] = UPDATED_NEW

    with pytest.raises(StalePlan):
        asyncio.run(spec.apply(connector, plan))
    assert puts == []


def test_update_comment_reconcile_fails_when_body_not_applied() -> None:
    state = _comment_state()
    connector = _connector({("GET", COMMENT_PATH): _comment_route(state)})
    spec = _spec("update_comment")
    plan = asyncio.run(spec.plan(connector, _update_args()))

    reconciled = asyncio.run(spec.reconcile(connector, plan))

    assert reconciled.status == "failed"
    assert reconciled.error == "comment body does not match the plan after write"


def test_add_remote_link_plan_is_noop_on_existing_global_id() -> None:
    existing = {"id": 7, "globalId": GLOBAL_ID, "object": {"url": URL, "title": "Item 42"}}
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(),
            ("GET", REMOTE_LINK_PATH): _links_route([existing]),
            ("POST", REMOTE_LINK_PATH): _recording_link_post(posts, []),
        }
    )
    spec = _spec("add_remote_link")

    plan = asyncio.run(spec.plan(connector, _link_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert plan.changed is False
    assert plan.target_ref == "jira_remote_link:7"
    assert outcome.status == "no_op"
    assert posts == []


def test_add_remote_link_apply_posts_exact_payload_and_reconciles() -> None:
    links: list[dict[str, Any]] = []
    posts: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(),
            ("GET", REMOTE_LINK_PATH): _links_route(links),
            ("POST", REMOTE_LINK_PATH): _recording_link_post(posts, links),
        }
    )
    spec = _spec("add_remote_link")

    plan = asyncio.run(spec.plan(connector, _link_args()))
    assert plan.changed is True
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "jira_remote_link:9001"
    assert [_body(request) for request in posts] == [
        {"globalId": GLOBAL_ID, "object": {"url": URL, "title": "Item 42"}}
    ]
    reconciled = asyncio.run(spec.reconcile(connector, plan))
    assert reconciled.status == "succeeded"
    assert reconciled.vendor_ref == "jira_remote_link:9001"


def test_add_remote_link_reconcile_fails_when_link_absent() -> None:
    connector = _connector(
        {
            ("GET", ISSUE_KEY_PATH): _issue_route(),
            ("GET", REMOTE_LINK_PATH): _links_route([]),
        }
    )
    spec = _spec("add_remote_link")
    plan = asyncio.run(spec.plan(connector, _link_args()))

    reconciled = asyncio.run(spec.reconcile(connector, plan))

    assert reconciled.status == "failed"
    assert reconciled.error == "remote link not found after write"


def test_list_comments_next_offset_is_none_on_short_page() -> None:
    comments = [{"id": "1", "body": "a"}, {"id": "2", "body": "b"}]
    connector = _connector({("GET", COMMENT_LIST_PATH): {"status": 200, "json": {"comments": comments}}})

    output = asyncio.run(_op("list_comments").fn(connector, ListCommentsArgs(issue_id_or_key="10001", max_results=5)))

    assert output.comments == comments
    assert output.next_start_at is None


def test_list_comments_next_offset_advances_on_full_page() -> None:
    comments = [{"id": str(index), "body": "x"} for index in range(3)]
    connector = _connector({("GET", COMMENT_LIST_PATH): {"status": 200, "json": {"comments": comments}}})

    output = asyncio.run(
        _op("list_comments").fn(connector, ListCommentsArgs(issue_id_or_key="10001", start_at=10, max_results=3))
    )

    assert output.next_start_at == 13


def test_list_remote_links_returns_links() -> None:
    links = [{"id": 7, "globalId": GLOBAL_ID, "object": {"url": URL, "title": "Item 42"}}]
    connector = _connector({("GET", REMOTE_LINK_PATH): _links_route(links)})

    output = asyncio.run(_op("list_remote_links").fn(connector, ListRemoteLinksArgs(issue_id_or_key="10001")))

    assert output.links == links


def test_get_edit_metadata_returns_fields() -> None:
    fields = {"summary": {"required": True}}
    connector = _connector({("GET", EDIT_META_PATH): {"status": 200, "json": {"fields": fields}}})

    output = asyncio.run(_op("get_edit_metadata").fn(connector, GetEditMetadataArgs(issue_id_or_key="10001")))

    assert output.fields == fields


def test_list_fields_and_projects_return_bare_arrays() -> None:
    connector = _connector(
        {
            ("GET", FIELD_PATH): {"status": 200, "json": [{"id": "summary", "name": "Summary"}]},
            ("GET", PROJECT_PATH): {"status": 200, "json": [{"key": "PROJ", "name": "Project"}]},
        }
    )

    fields = asyncio.run(_op("list_fields").fn(connector, ListFieldsArgs()))
    projects = asyncio.run(_op("list_projects").fn(connector, ListProjectsArgs()))

    assert fields.fields == [{"id": "summary", "name": "Summary"}]
    assert projects.projects == [{"key": "PROJ", "name": "Project"}]


def test_models_reject_extra_fields() -> None:
    with pytest.raises(pydantic.ValidationError):
        UpdateCommentArgs(
            issue_id_or_key="PROJ-1",
            comment_id="555",
            expected_updated=UPDATED_OLD,
            body="x",
            unexpected="y",  # type: ignore[call-arg]
        )
    with pytest.raises(pydantic.ValidationError):
        AddRemoteLinkArgs(issue_id_or_key="PROJ-1", global_id=GLOBAL_ID, url=URL, title="t", unexpected="y")  # type: ignore[call-arg]
