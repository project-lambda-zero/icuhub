"""Action state machine against a recorded vendor and real Postgres (HLD 6.3)."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest

from icuhub.core.actions import decide, run_apply_job, run_reconcile_job, submit_action
from icuhub.core.audit import verify_chain
from icuhub.kit.errors import Conflict, PermissionDenied
from icuhub.storage.db import session_scope
from icuhub.storage.models import Approval, Tenant
from tests.core.helpers import caller_for, make_services, new_connection, vendor_transport


def _setup(tmp_path: Any, state: dict[str, Any]) -> Any:
    return make_services(vendor_transport(state), tmp_path / "kek")


def _tenant_slug(tenant_id: uuid.UUID) -> str:
    return f"t-{tenant_id.hex[:8]}"


async def _new_tracker(services: Any, tenant_id: uuid.UUID) -> Any:
    async with session_scope(tenant_id) as session:
        session.add(Tenant(id=tenant_id, slug=_tenant_slug(tenant_id), display_name="T"))
        await session.flush()
        return await new_connection(session, services, tenant_id, kind="sample_tracker_core")


def test_full_approval_flow_and_audit(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": []}
        services = _setup(tmp_path, state)
        tenant_id = uuid.uuid4()
        connection = await _new_tracker(services, tenant_id)
        async with session_scope(tenant_id) as session:
            from icuhub.storage.models import PolicyRule  # noqa: PLC0415

            session.add(
                PolicyRule(
                    tenant_id=tenant_id,
                    priority=1,
                    name="jira-writes-need-secops",
                    match_json={"operations": ["create_issue"]},
                    decision="require_approval",
                    approver_group="secops",
                )
            )
            await session.flush()
            request = await submit_action(
                session,
                caller_for(tenant_id, "requester"),
                connection.id,
                "create_issue",
                {"summary": "fix CVE", "route_key": "rk-1"},
                idempotency_key="key-1",
            )
            assert request.state == "pending_approval"
            approval = (
                await session.execute(__import__("sqlalchemy").select(Approval))
            ).scalar_one()
            assert approval.plan_hash
            with pytest.raises(PermissionDenied):
                await decide(session, caller_for(tenant_id, "requester"), approval.id, "approved")
            with pytest.raises(PermissionDenied):
                await decide(session, caller_for(tenant_id, "outsider", roles={"approver"}, groups={"other"}), approval.id, "approved")
            await decide(session, caller_for(tenant_id, "approver", roles={"approver"}), approval.id, "approved")
            assert request.state == "approved"
        async with session_scope(tenant_id) as session:
            outcome = await run_apply_job({"action_request_id": str(request.id), "tenant_id": str(tenant_id)})
            assert outcome["state"] == "succeeded"
            from icuhub.storage.models import ActionRequest  # noqa: PLC0415

            fresh = await session.get(ActionRequest, request.id)
            assert fresh.result_json["vendor_ref"] == "ISSUE-1"
            assert state["issues"][0]["summary"] == "fix CVE"
            chain = await verify_chain(session, tenant_id)
            assert chain.ok, chain
        async with session_scope(tenant_id) as session:
            replay = await submit_action(
                session,
                caller_for(tenant_id, "requester"),
                connection.id,
                "create_issue",
                {"summary": "fix CVE", "route_key": "rk-1"},
                idempotency_key="key-1",
            )
            assert replay.id == request.id
            with pytest.raises(Conflict):
                await submit_action(
                    session,
                    caller_for(tenant_id, "requester"),
                    connection.id,
                    "create_issue",
                    {"summary": "different"},
                    idempotency_key="key-1",
                )

    asyncio.run(scenario())


def test_no_op_stale_plan_and_unknown_reconcile(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [{"key": "ISSUE-1", "route_key": "rk-dup"}]}
        services = _setup(tmp_path, state)
        tenant_id = uuid.uuid4()
        connection = await _new_tracker(services, tenant_id)
        async with session_scope(tenant_id) as session:
            noop = await submit_action(
                session,
                caller_for(tenant_id, "requester"),
                connection.id,
                "create_issue",
                {"summary": "dup", "route_key": "rk-dup"},
                idempotency_key="key-noop",
            )
            assert noop.state == "no_op"
            assert len(state["issues"]) == 1
            stale = await submit_action(
                session,
                caller_for(tenant_id, "requester"),
                connection.id,
                "create_issue",
                {"summary": "stale", "route_key": "rk-stale"},
                idempotency_key="key-stale",
            )
            approval = (
                await session.execute(
                    __import__("sqlalchemy").select(Approval).where(Approval.action_request_id == stale.id)
                )
            ).scalar_one()
            await decide(session, caller_for(tenant_id, "approver", roles={"approver"}), approval.id, "approved")
            state["issues"].append({"key": "ISSUE-2", "route_key": "rk-stale"})
        async with session_scope(tenant_id) as session:
            outcome = await run_apply_job({"action_request_id": str(stale.id), "tenant_id": str(tenant_id)})
            assert outcome["state"] == "stale_plan"
        state["issues"].clear()
        async with session_scope(tenant_id) as session:
            unknown = await submit_action(
                session,
                caller_for(tenant_id, "requester"),
                connection.id,
                "create_issue",
                {"summary": "unknown", "route_key": "rk-unknown"},
                idempotency_key="key-unknown",
            )
            approval = (
                await session.execute(
                    __import__("sqlalchemy").select(Approval).where(Approval.action_request_id == unknown.id)
                )
            ).scalar_one()
            await decide(session, caller_for(tenant_id, "approver", roles={"approver"}), approval.id, "approved")
        async with session_scope(tenant_id) as session:
            outcome = await run_apply_job({"action_request_id": str(unknown.id), "tenant_id": str(tenant_id)})
            assert outcome["state"] == "outcome_unknown"
        async with session_scope(tenant_id) as session:
            pending = await run_reconcile_job({"action_request_id": str(unknown.id), "tenant_id": str(tenant_id)})
            assert pending["state"] == "outcome_unknown"
            state["issues"].append({"key": "ISSUE-9", "route_key": "rk-unknown"})
            resolved = await run_reconcile_job({"action_request_id": str(unknown.id), "tenant_id": str(tenant_id)})
            assert resolved["state"] == "succeeded"

    asyncio.run(scenario())


def test_accepted_async_reconciles_without_reapply(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": []}
        services = _setup(tmp_path, state)
        tenant_id = uuid.uuid4()
        connection = await _new_tracker(services, tenant_id)
        async with session_scope(tenant_id) as session:
            request = await submit_action(
                session,
                caller_for(tenant_id, "requester"),
                connection.id,
                "create_issue",
                {"summary": "async", "route_key": "rk-async"},
                idempotency_key="key-async",
            )
            approval = (
                await session.execute(
                    __import__("sqlalchemy").select(Approval).where(Approval.action_request_id == request.id)
                )
            ).scalar_one_or_none()
            if approval is not None:
                await decide(session, caller_for(tenant_id, "approver", roles={"approver"}), approval.id, "approved")
        payload = {"action_request_id": str(request.id), "tenant_id": str(tenant_id)}
        async with session_scope(tenant_id) as session:
            applied = await run_apply_job(payload)
            assert applied["state"] == "accepted_async"
        async with session_scope(tenant_id) as session:
            # Apply on an accepted_async request must be a no-op, never a second vendor write.
            again = await run_apply_job(payload)
            assert again["skipped"] is True
        assert state.get("ticket", {}).get("polls", 0) == 0
        for _ in range(3):
            async with session_scope(tenant_id) as session:
                step = await run_reconcile_job(payload)
        assert step["state"] == "succeeded"
        assert len(state["issues"]) == 1
        assert state["ticket"]["polls"] == 3
        async with session_scope(tenant_id) as session:
            from icuhub.storage.models import ActionRequest  # noqa: PLC0415

            fresh = await session.get(ActionRequest, request.id)
            assert fresh.state == "succeeded"
            assert fresh.result_json["vendor_ref"] == "ISSUE-7"

    asyncio.run(scenario())


def test_apply_failure_is_terminal_and_never_retried(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "create_fails": True}
        services = _setup(tmp_path, state)
        tenant_id = uuid.uuid4()
        connection = await _new_tracker(services, tenant_id)
        async with session_scope(tenant_id) as session:
            request = await submit_action(
                session,
                caller_for(tenant_id, "requester"),
                connection.id,
                "create_issue",
                {"summary": "boom", "route_key": "rk-fail"},
                idempotency_key="key-fail",
            )
            approval = (
                await session.execute(
                    __import__("sqlalchemy").select(Approval).where(Approval.action_request_id == request.id)
                )
            ).scalar_one_or_none()
            if approval is not None:
                await decide(session, caller_for(tenant_id, "approver", roles={"approver"}), approval.id, "approved")
        payload = {"action_request_id": str(request.id), "tenant_id": str(tenant_id)}
        async with session_scope(tenant_id) as session:
            failed = await run_apply_job(payload)
            assert failed["state"] == "failed"
        async with session_scope(tenant_id) as session:
            again = await run_apply_job(payload)
            assert again["skipped"] is True
        assert state["issues"] == []

    asyncio.run(scenario())


def test_destructive_requires_approval_even_with_switches(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": []}
        services = _setup(tmp_path, state)
        tenant_id = uuid.uuid4()
        connection = await _new_tracker(services, tenant_id)
        async with session_scope(tenant_id) as session:
            tenant = await session.get(Tenant, tenant_id)
            tenant.automation_enabled = True
            services.settings = services.settings.model_copy(update={"automation_enabled": True})
            request = await submit_action(
                session,
                caller_for(tenant_id, "requester"),
                connection.id,
                "delete_issue",
                {"summary": "ISSUE-1"},
                idempotency_key="key-del",
            )
            assert request.state == "pending_approval"

    asyncio.run(scenario())
