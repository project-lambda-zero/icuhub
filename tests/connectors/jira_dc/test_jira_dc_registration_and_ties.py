"""Focused tests for DC webhook registration paths, the bounded timestamp-tie cursor, and field reconcile outcomes.

Each assertion pins behavior the connector implements. The Jira 10 registration element path and the Jira 10
status codes are [UNVERIFIED] upstream; these tests do not treat them as vendor fact.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest

from icuhub.connectors._jira.models import DeleteWebhookInput
from icuhub.connectors.jira_dc import JiraDataCenter
from icuhub.connectors.jira_dc.webhook_registration import (
    CreateDcWebhookInput,
    RegistrationFamily,
    delete_path,
    registration_path,
)
from icuhub.kit.errors import ConnectorError
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector
from icuhub.kit.types import ActionOutcome, ActionPlan

BASE = "https://jira.example.test"
PAT_REF = "jira-pat"
SECRETS = {PAT_REF: b"synthetic-pat"}
SAME_TS = "2026-11-01T09:15:00.000+0000"
HOOK_URL = "https://hook.example.test/a"
SERVER_INFO = "/rest/api/2/serverInfo"
ISSUE_ID_PATH = "/rest/api/2/issue/10001"


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> JiraDataCenter:
    config = {"base_url": BASE, "personal_access_token": {"ref": PAT_REF}, **config_extra}
    return cast(JiraDataCenter, make_connector(JiraDataCenter, config, RouteTransport(routes), SECRETS))


def _server(version: list[int]) -> dict[tuple[str, str], Any]:
    return {("GET", SERVER_INFO): {"status": 200, "json": {"versionNumbers": version}}}


def _issues(count: int) -> dict[str, Any]:
    issues = [
        {"id": str(10_000 + index), "key": f"PROJ-{index}", "fields": {"updated": SAME_TS}} for index in range(count)
    ]
    return {"startAt": 0, "maxResults": count, "total": count, "issues": issues}


def _registration(webhook_id: str = "wh-1") -> dict[str, Any]:
    return {"id": webhook_id, "name": "hook", "url": HOOK_URL, "events": ["jira:issue_created"]}


# --- registration paths -----------------------------------------------------


@pytest.mark.parametrize(
    ("family", "collection"),
    [
        ("pre_10", "/rest/webhooks/1.0/webhook"),
        ("jira_10", "/rest/jira-webhook/1.0/webhooks"),
    ],
)
def test_registration_path_returns_family_collection(family: RegistrationFamily, collection: str) -> None:
    assert registration_path(family) == collection


@pytest.mark.parametrize(
    ("family", "collection"),
    [
        ("pre_10", "/rest/webhooks/1.0/webhook"),
        ("jira_10", "/rest/jira-webhook/1.0/webhooks"),
    ],
)
def test_delete_path_appends_percent_encoded_id_to_family_collection(family: RegistrationFamily, collection: str) -> None:
    assert delete_path(family, "a/b c") == f"{collection}/a%2Fb%20c"


def test_delete_plan_on_jira_10_carries_family_and_jira_10_delete_path() -> None:
    connector = _connector(
        {
            **_server([10, 0, 0]),
            ("GET", "/rest/jira-webhook/1.0/webhooks"): {"status": 200, "json": [_registration()]},
        },
        destructive_enabled=True,
    )

    plan = asyncio.run(connector.plan_delete_webhook(DeleteWebhookInput(webhook_id="wh-1", expected_url=HOOK_URL)))

    assert plan.changed is True
    assert plan.request == {
        "method": "DELETE",
        "path": "/rest/jira-webhook/1.0/webhooks/wh-1",
        "family": "jira_10",
    }


def test_delete_plan_on_pre_10_carries_family_and_pre_10_delete_path() -> None:
    connector = _connector(
        {
            **_server([9, 4, 0]),
            ("GET", "/rest/webhooks/1.0/webhook"): {"status": 200, "json": [_registration()]},
        },
        destructive_enabled=True,
    )

    plan = asyncio.run(connector.plan_delete_webhook(DeleteWebhookInput(webhook_id="wh-1", expected_url=HOOK_URL)))

    assert plan.request == {
        "method": "DELETE",
        "path": "/rest/webhooks/1.0/webhook/wh-1",
        "family": "pre_10",
    }


def test_create_plan_on_pre_10_posts_to_family_collection_with_documented_body() -> None:
    connector = _connector(
        {
            **_server([9, 4, 0]),
            ("GET", "/rest/webhooks/1.0/webhook"): {"status": 200, "json": []},
        },
    )
    args = CreateDcWebhookInput(name="hook", url=HOOK_URL, events=["jira:issue_created"], jql_filter="project = PROJ")

    plan = asyncio.run(connector.plan_create_webhook(args))

    assert plan.changed is True
    assert plan.request["method"] == "POST"
    assert plan.request["path"] == "/rest/webhooks/1.0/webhook"
    assert plan.request["family"] == "pre_10"
    assert plan.request["json"] == {
        "name": "hook",
        "url": HOOK_URL,
        "events": ["jira:issue_created"],
        "excludeBody": False,
        "filters": {"issue-related-events-section": "project = PROJ"},
    }


# --- bounded timestamp-tie cursor -------------------------------------------


def test_issues_stream_raises_when_timestamp_ties_exceed_max_tie_ids() -> None:
    connector = _connector(
        {("GET", "/rest/api/2/search"): {"status": 200, "json": _issues(101)}},
        max_tie_ids=100,
        page_size=200,
    )

    with pytest.raises(ConnectorError, match="max_tie_ids"):
        collect_stream(connector, "issues", mode="full")


def test_issues_stream_accepts_timestamp_ties_at_max_tie_ids_bound() -> None:
    connector = _connector(
        {("GET", "/rest/api/2/search"): {"status": 200, "json": _issues(100)}},
        max_tie_ids=100,
        page_size=200,
    )

    batches = collect_stream(connector, "issues", mode="full")

    assert sum(len(batch.records) for batch in batches) == 100


# --- update_issue_fields reconcile ------------------------------------------


def _update_plan(fields: dict[str, Any]) -> ActionPlan:
    return ActionPlan(
        action="update_issue_fields",
        target_ref="jira_issue:10001",
        diff={"fields": fields},
        preconditions={"id": "10001"},
        idempotency_key="key",
        changed=True,
        request={"method": "PUT", "path": ISSUE_ID_PATH},
    )


def _reconcile(issue_fields: dict[str, Any], requested: dict[str, Any]) -> ActionOutcome:
    connector = _connector({("GET", ISSUE_ID_PATH): {"status": 200, "json": {"id": "10001", "fields": issue_fields}}})
    plan = _update_plan(requested)
    spec: Any = JiraDataCenter.actions()["update_issue_fields"]
    prior = ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)
    return asyncio.run(spec.reconcile(connector, plan, prior))


def test_reconcile_update_issue_fields_is_unverified_when_requested_field_is_omitted() -> None:
    # The field is absent from the read-back, which field-level permissions can cause; absence alone
    # does not prove the approved state is missing.
    result = _reconcile(issue_fields={}, requested={"summary": "Renamed"})

    assert result.status == "unverified"
    assert result.error == "requested fields are not readable"


def test_reconcile_update_issue_fields_fails_when_present_field_holds_wrong_value() -> None:
    result = _reconcile(issue_fields={"summary": "Original"}, requested={"summary": "Renamed"})

    assert result.status == "failed"
    assert result.error == "requested field values do not match the plan"


def test_reconcile_update_issue_fields_succeeds_when_every_requested_field_matches() -> None:
    result = _reconcile(issue_fields={"summary": "Renamed"}, requested={"summary": "Renamed"})

    assert result.status == "succeeded"
