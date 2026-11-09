"""Action gate tests for the Fortify SSC connector.

Covers ``audit_issue`` (plan, no-op, revision precondition, apply, reconcile) and the
destructive purge actions, which are gated by ``destructive_enabled``. Actions are
invoked through their ``ActionSpec`` (``plan``, ``apply``, ``reconcile``), each of
which takes the connector as the first argument.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, cast

import pytest

from icuhub.connectors.fortify_ssc import FortifySsc
from icuhub.connectors.fortify_ssc.models import (
    AuditIssueArgs,
    PurgeArtifactArgs,
    PurgeProjectVersionArgs,
)
from icuhub.kit.errors import PermissionDenied, StalePlan
from icuhub.kit.testing import RouteTransport, make_connector
from icuhub.kit.types import ActionPlan

BASE = "https://ssc.example.test/ssc"
API = "/ssc/api/v1"
TOKEN_REF = "fortify-token"
SECRETS = {TOKEN_REF: b"fixture-token"}
ISSUE_PATH = f"{API}/projectVersions/42/issues/1001"
AUDIT_PATH = f"{ISSUE_PATH}/audit"


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> FortifySsc:
    config: dict[str, Any] = {"base_url": BASE, "api_token": {"ref": TOKEN_REF}, **config_extra}
    return cast(FortifySsc, make_connector(FortifySsc, config, RouteTransport(routes), SECRETS))


def _issue_state(state: dict[str, Any]) -> Any:
    """GET issue route that reflects the mutable ``state`` at call time."""

    def handler(_request: Any) -> dict[str, Any]:
        state.setdefault("gets", 0)
        state["gets"] += 1
        return {
            "status": 200,
            "json": {
                "data": {
                    "revision": state["revision"],
                    "auditState": state["auditState"],
                    "suppressed": False,
                    "assignee": None,
                }
            },
        }

    return handler


def _audit_args(revision: int = 3, audit_state: str = "Audited") -> AuditIssueArgs:
    return AuditIssueArgs(
        project_version_id=42,
        issue_id=1001,
        revision=revision,
        audit_state=audit_state,
        comment=None,
    )


def _audit_spec() -> Any:
    return FortifySsc.actions()["audit_issue"]


# --- audit_issue -----------------------------------------------------------


def test_audit_issue_plan_describes_state_change() -> None:
    state = {"revision": 3, "auditState": "Unaudited"}
    connector = _connector({("GET", ISSUE_PATH): _issue_state(state)})
    spec = _audit_spec()

    plan: ActionPlan = asyncio.run(spec.plan(connector, _audit_args()))

    assert plan.changed is True
    assert plan.target_ref == "fortify_ssc:issue:42:1001"
    assert plan.diff == {"auditState": {"from": "Unaudited", "to": "Audited"}}
    assert plan.preconditions == {"revision": 3}
    assert plan.idempotency_key == "audit:42:1001:3:Audited"
    assert plan.request["method"] == "POST"
    assert plan.request["path"] == "/api/v1/projectVersions/42/issues/1001/audit"
    assert plan.request["json"] == {"auditState": "Audited", "comment": None, "revision": 3}


def test_audit_issue_unchanged_state_is_no_op_without_http() -> None:
    state = {"revision": 3, "auditState": "Audited"}
    seen: list[Any] = []
    base_get = _issue_state(state)

    def counting_get(request: Any) -> dict[str, Any]:
        seen.append(request)
        return base_get(request)

    connector = _connector({("GET", ISSUE_PATH): counting_get})
    spec = _audit_spec()

    plan = asyncio.run(spec.plan(connector, _audit_args()))
    assert plan.changed is False

    before_apply = len(seen)
    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "no_op"
    assert len(seen) == before_apply


def test_audit_issue_apply_refuses_when_revision_moved() -> None:
    state = {"revision": 3, "auditState": "Unaudited"}
    connector = _connector({("GET", ISSUE_PATH): _issue_state(state)})
    spec = _audit_spec()

    plan = asyncio.run(spec.plan(connector, _audit_args()))
    state["revision"] = 4

    with pytest.raises(StalePlan, match="moved to revision 4"):
        asyncio.run(spec.apply(connector, plan))


def test_audit_issue_apply_posts_and_reports_new_state() -> None:
    state = {"revision": 3, "auditState": "Unaudited"}
    posted: list[Any] = []

    def post(request: Any) -> dict[str, Any]:
        posted.append(json.loads(request.content))
        return {"status": 200, "json": {"data": {"auditState": "Audited"}}}

    connector = _connector(
        {
            ("GET", ISSUE_PATH): _issue_state(state),
            ("POST", AUDIT_PATH): post,
        }
    )
    spec = _audit_spec()

    plan = asyncio.run(spec.plan(connector, _audit_args()))
    outcome = asyncio.run(spec.apply(connector, plan))

    assert posted == [{"auditState": "Audited", "comment": None, "revision": 3}]
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "fortify_ssc:issue:42:1001"
    assert outcome.result == {"auditState": "Audited"}


def test_audit_issue_reconcile_confirms_requested_state() -> None:
    state = {"revision": 3, "auditState": "Unaudited"}
    connector = _connector({("GET", ISSUE_PATH): _issue_state(state)})
    spec = _audit_spec()

    plan = asyncio.run(spec.plan(connector, _audit_args()))
    state["auditState"] = "Audited"
    outcome = asyncio.run(spec.reconcile(connector, plan))

    assert outcome.status == "succeeded"
    assert outcome.result == {"reconciled": True}


def test_audit_issue_reconcile_fails_when_state_did_not_converge() -> None:
    state = {"revision": 3, "auditState": "Unaudited"}
    connector = _connector({("GET", ISSUE_PATH): _issue_state(state)})
    spec = _audit_spec()

    plan = asyncio.run(spec.plan(connector, _audit_args()))
    outcome = asyncio.run(spec.reconcile(connector, plan))

    assert outcome.status == "failed"


# --- destructive purge actions --------------------------------------------


def test_purge_project_version_denied_without_destructive_flag() -> None:
    connector = _connector({})
    spec = FortifySsc.actions()["purge_project_version"]
    args = PurgeProjectVersionArgs(project_version_id=42, approval_ref="CHG-1")

    with pytest.raises(PermissionDenied):
        asyncio.run(spec.plan(connector, args))


def test_purge_project_version_plan_and_apply_when_destructive_enabled() -> None:
    seen: list[Any] = []

    def delete(request: Any) -> dict[str, Any]:
        seen.append(request)
        return {"status": 204, "text": ""}

    connector = _connector(
        {("DELETE", f"{API}/projectVersions/42"): delete},
        destructive_enabled=True,
    )
    spec = FortifySsc.actions()["purge_project_version"]
    args = PurgeProjectVersionArgs(project_version_id=42, approval_ref="CHG-1")

    plan = asyncio.run(spec.plan(connector, args))

    assert plan.changed is True
    assert plan.target_ref == "fortify_ssc:project_version:42"
    assert plan.request == {"method": "DELETE", "path": "/api/v1/projectVersions/42"}
    assert plan.idempotency_key == "purge-pv:42:CHG-1"
    assert plan.preconditions == {"approval_ref": "CHG-1"}

    outcome = asyncio.run(spec.apply(connector, plan))

    assert outcome.status == "succeeded"
    assert len(seen) == 1


def test_purge_artifact_denied_without_destructive_flag() -> None:
    connector = _connector({})
    spec = FortifySsc.actions()["purge_artifact"]
    args = PurgeArtifactArgs(artifact_id=501, version_number=1, approval_ref="CHG-1")

    with pytest.raises(PermissionDenied):
        asyncio.run(spec.plan(connector, args))
