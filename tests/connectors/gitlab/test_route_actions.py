"""RouteTransport tests for GitLab governed merge-request actions over the real HTTP client."""

from __future__ import annotations

import asyncio
import json
from typing import Any, ClassVar, cast

import pytest

from icuhub.connectors._gitlab.actions import (
    apply_approve_merge_request,
    apply_create_merge_request,
    apply_merge_merge_request,
    plan_approve_merge_request,
    plan_create_merge_request,
    plan_merge_merge_request,
)
from icuhub.connectors._gitlab.connector import GitLabConnectorBase
from icuhub.connectors._gitlab.models import (
    ApproveMergeRequestArgs,
    CreateMergeRequestArgs,
    GitLabConfig,
    MergeMergeRequestArgs,
)
from icuhub.kit import ActionOutcome, ActionPlan, ConfigError, ConnectorConfig, StalePlan
from icuhub.kit.testing import RouteTransport, make_connector

PROJECT_ID = 42
IID = 7
MR_ID = 1007
API = "/api/v4"
MR_COLLECTION = ("GET", f"{API}/projects/{PROJECT_ID}/merge_requests")
MR_CREATE = ("POST", f"{API}/projects/{PROJECT_ID}/merge_requests")
MR_ITEM = ("GET", f"{API}/projects/{PROJECT_ID}/merge_requests/{IID}")
APPROVALS = ("GET", f"{API}/projects/{PROJECT_ID}/merge_requests/{IID}/approvals")
APPROVE = ("POST", f"{API}/projects/{PROJECT_ID}/merge_requests/{IID}/approve")
MERGE = ("PUT", f"{API}/projects/{PROJECT_ID}/merge_requests/{IID}/merge")
TOKEN_REF = "gitlab-token"
SECRETS = {TOKEN_REF: b"glpat-synthetic"}
HEAD = "89abcdef0123456789abcdef0123456789abcdef"
MERGE_COMMIT = "fedcba9876543210fedcba9876543210fedcba98"
SOURCE = "fix/cve-2026-1234"
TARGET = "main"


class _RouteGitLab(GitLabConnectorBase):
    """Concrete test connector: the shared GitLab base plus the class attributes an edition package supplies."""

    kind: ClassVar[str] = "gitlab"
    display_name: ClassVar[str] = "GitLab (route test)"
    config_model: ClassVar[type[ConnectorConfig]] = GitLabConfig
    flows: ClassVar[tuple[str, ...]] = ()


def _mr() -> dict[str, Any]:
    return {
        "id": MR_ID,
        "iid": IID,
        "sha": HEAD,
        "state": "opened",
        "source_branch": SOURCE,
        "target_branch": TARGET,
    }


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> _RouteGitLab:
    config: dict[str, Any] = {"access_token": {"ref": TOKEN_REF}, "write_enabled": True, **config_extra}
    return cast(_RouteGitLab, make_connector(_RouteGitLab, config, RouteTransport(routes), SECRETS))


def _args() -> CreateMergeRequestArgs:
    return CreateMergeRequestArgs(
        project_id=PROJECT_ID,
        source_branch=SOURCE,
        target_branch=TARGET,
        title="Fix parser bounds",
        description=None,
        action_key="mr-create-0001",
        approved_plan_hash="0" * 64,
    )


def test_create_merge_request_plans_posts_and_reads_back() -> None:
    sent: list[dict[str, Any]] = []

    def create(request: Any) -> dict[str, Any]:
        sent.append(json.loads(request.content))
        return {"status": 201, "json": _mr()}

    connector = _connector(
        {
            MR_COLLECTION: {"status": 200, "json": []},
            MR_CREATE: create,
            MR_ITEM: {"status": 200, "json": _mr()},
        }
    )

    async def run() -> tuple[ActionPlan, ActionOutcome]:
        plan = await plan_create_merge_request(connector, _args())
        outcome = await apply_create_merge_request(connector, plan)
        return plan, outcome

    plan, outcome = asyncio.run(run())
    assert plan.changed is True
    assert plan.preconditions == {"open_merge_request_iid": None}
    assert sent[0]["source_branch"] == SOURCE
    assert sent[0]["target_branch"] == TARGET
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == str(MR_ID)
    assert outcome.result == {"id": MR_ID, "iid": IID, "project_id": PROJECT_ID}


def test_existing_open_merge_request_is_a_noop_without_post() -> None:
    # Only the collection GET is routed: any POST would fail the transport with AssertionError.
    connector = _connector({MR_COLLECTION: {"status": 200, "json": [_mr()]}})

    async def run() -> tuple[ActionPlan, ActionOutcome]:
        plan = await plan_create_merge_request(connector, _args())
        outcome = await apply_create_merge_request(connector, plan)
        return plan, outcome

    plan, outcome = asyncio.run(run())
    assert plan.changed is False
    assert outcome.status == "no_op"
    assert outcome.vendor_ref == str(MR_ID)


def test_apply_refuses_when_open_merge_request_appears_after_plan() -> None:
    lookups = {"count": 0}

    def collection(_request: Any) -> dict[str, Any]:
        lookups["count"] += 1
        return {"status": 200, "json": [] if lookups["count"] == 1 else [_mr()]}

    connector = _connector({MR_COLLECTION: collection})

    async def run() -> None:
        plan = await plan_create_merge_request(connector, _args())
        await apply_create_merge_request(connector, plan)

    with pytest.raises(StalePlan):
        asyncio.run(run())


def test_apply_fails_closed_when_writes_are_disabled() -> None:
    connector = _connector({MR_COLLECTION: {"status": 200, "json": []}}, write_enabled=False)

    async def run() -> ActionOutcome:
        plan = await plan_create_merge_request(connector, _args())
        return await apply_create_merge_request(connector, plan)

    with pytest.raises(ConfigError, match="writes are disabled"):
        asyncio.run(run())


def test_approve_merge_request_plans_posts_and_reads_back_at_planned_head() -> None:
    state = {"approved": False}
    sent: list[dict[str, Any]] = []

    def approvals(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": {"approved": state["approved"]}}

    def approve(request: Any) -> dict[str, Any]:
        sent.append(json.loads(request.content))
        state["approved"] = True
        return {"status": 201, "json": {"approved": True}}

    connector = _connector({MR_ITEM: {"status": 200, "json": _mr()}, APPROVALS: approvals, APPROVE: approve})
    args = ApproveMergeRequestArgs(
        project_id=PROJECT_ID,
        iid=IID,
        sha=HEAD,
        action_key="mr-approve-0001",
        approved_plan_hash="0" * 64,
    )

    async def run() -> tuple[ActionPlan, ActionOutcome]:
        plan = await plan_approve_merge_request(connector, args)
        outcome = await apply_approve_merge_request(connector, plan)
        return plan, outcome

    plan, outcome = asyncio.run(run())
    assert plan.changed is True
    assert sent == [{"sha": HEAD}]
    assert outcome.status == "succeeded"
    assert outcome.result == {"project_id": PROJECT_ID, "iid": IID, "sha": HEAD}


def test_merge_merge_request_reads_back_merged_at_planned_head() -> None:
    state = {"merged": False}
    sent: list[dict[str, Any]] = []

    def item(_request: Any) -> dict[str, Any]:
        if state["merged"]:
            return {
                "status": 200,
                "json": {**_mr(), "state": "merged", "merge_commit_sha": MERGE_COMMIT},
            }
        return {"status": 200, "json": _mr()}

    def merge(request: Any) -> dict[str, Any]:
        sent.append(json.loads(request.content))
        state["merged"] = True
        return {"status": 200, "json": {"state": "merged"}}

    connector = _connector(
        {MR_ITEM: item, MERGE: merge},
        destructive_enabled=True,
    )
    args = MergeMergeRequestArgs(
        project_id=PROJECT_ID,
        iid=IID,
        sha=HEAD,
        action_key="mr-merge-0001",
        approved_plan_hash="0" * 64,
    )

    async def run() -> tuple[ActionPlan, ActionOutcome]:
        plan = await plan_merge_merge_request(connector, args)
        outcome = await apply_merge_merge_request(connector, plan)
        return plan, outcome

    plan, outcome = asyncio.run(run())
    assert plan.changed is True
    assert sent == [{"sha": HEAD}]
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == str(MR_ID)
    assert outcome.result == {
        "project_id": PROJECT_ID,
        "iid": IID,
        "sha": HEAD,
        "id": MR_ID,
        "merge_commit_sha": MERGE_COMMIT,
    }


def test_merge_fails_closed_when_destructive_actions_are_disabled() -> None:
    # Only the MR read is routed: a merge PUT would fail the transport with AssertionError.
    connector = _connector({MR_ITEM: {"status": 200, "json": _mr()}}, destructive_enabled=False)
    args = MergeMergeRequestArgs(
        project_id=PROJECT_ID,
        iid=IID,
        sha=HEAD,
        action_key="mr-merge-0002",
        approved_plan_hash="0" * 64,
    )

    async def run() -> ActionOutcome:
        plan = await plan_merge_merge_request(connector, args)
        return await apply_merge_merge_request(connector, plan)

    with pytest.raises(ConfigError, match="destructive actions are disabled"):
        asyncio.run(run())
