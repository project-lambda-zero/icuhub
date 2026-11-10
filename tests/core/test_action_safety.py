"""Action safety: plan-time write guard, approver gate, and the unverified terminal (HLD 6.3, FR-ADM-03)."""

from __future__ import annotations

import asyncio
import inspect
import uuid
from typing import Any

import pytest
from sqlalchemy import select

from icuhub.core.actions import _ReadOnlyHttp, decide, submit_action
from icuhub.kit.errors import PermissionDenied
from icuhub.kit.http import VendorHttp
from icuhub.kit.types import ActionOutcome
from icuhub.storage.db import session_scope
from icuhub.storage.models import Approval, PolicyRule, Tenant
from tests.core.helpers import caller_for, make_services, new_connection, vendor_transport


class _RecordingHttp:
    """Inner VendorHttp stand-in that records every call it receives."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def request(self, method: str, path_or_url: str, **kwargs: Any) -> str:
        self.calls.append((method, path_or_url))
        return "sent"

    async def stream_download(self, method: str, url: str, *, max_bytes: int, headers: Any = None) -> str:
        self.calls.append((method, url))
        return "sent"

    async def stream_download_result(
        self,
        method: str,
        url: str,
        *,
        max_bytes: int,
        params: Any = None,
        headers: Any = None,
        expected: Any = (200,),
    ) -> str:
        self.calls.append((method, url))
        return "sent"


def test_read_only_http_rejects_writes_on_every_request_method() -> None:
    async def scenario() -> None:
        inner = _RecordingHttp()
        guard = _ReadOnlyHttp(inner)
        with pytest.raises(AssertionError):
            await guard.request("POST", "https://vendor.example/api/x")
        with pytest.raises(AssertionError):
            await guard.request("PUT", "https://vendor.example/api/x")
        with pytest.raises(AssertionError):
            await guard.stream_download("POST", "https://vendor.example/api/x", max_bytes=10)
        with pytest.raises(AssertionError):
            await guard.stream_download_result("DELETE", "https://vendor.example/api/x", max_bytes=10)
        assert inner.calls == []

    asyncio.run(scenario())


def test_read_only_http_passes_reads_and_allowed_posts() -> None:
    async def scenario() -> None:
        inner = _RecordingHttp()
        guard = _ReadOnlyHttp(inner, allowed_post_paths=("/api/search", "/api/query/"))
        await guard.request("GET", "https://vendor.example/api/x")
        await guard.stream_download("GET", "https://vendor.example/api/x", max_bytes=10)
        await guard.stream_download_result("HEAD", "https://vendor.example/api/x", max_bytes=10)
        await guard.request("POST", "https://vendor.example/api/search")
        await guard.request("POST", "https://vendor.example/api/query/deep/one")
        with pytest.raises(AssertionError):
            await guard.request("POST", "https://vendor.example/api/search/extra")
        assert [verb for verb, _ in inner.calls] == ["GET", "GET", "HEAD", "POST", "POST"]

    asyncio.run(scenario())


def test_read_only_http_covers_every_public_vendor_coroutine() -> None:
    public = {
        name
        for name, member in inspect.getmembers(VendorHttp)
        if not name.startswith("_") and name != "aclose" and inspect.iscoroutinefunction(member)
    }
    assert public, "VendorHttp must expose request-issuing coroutines"
    missing = {name for name in public if name not in _ReadOnlyHttp.__dict__}
    assert not missing, f"_ReadOnlyHttp would forward these unguarded: {sorted(missing)}"


def test_action_outcome_accepts_unverified() -> None:
    outcome = ActionOutcome(status="unverified", error="read-back could not establish approved state")
    assert outcome.status == "unverified"


async def _pending_approval(tenant_id: uuid.UUID, tmp_path: Any) -> tuple[Any, uuid.UUID]:
    services = make_services(vendor_transport({"issues": []}), tmp_path / "kek")
    async with session_scope(tenant_id) as session:
        session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
        await session.flush()
        connection = await new_connection(session, services, tenant_id, kind="sample_tracker_core")
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
            idempotency_key="key-safety",
        )
        assert request.state == "pending_approval"
    return services, uuid.UUID(str(request.id))


def test_decide_refuses_admin_and_auditor_without_approver_role(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        _services, request_id = await _pending_approval(tenant_id, tmp_path)
        async with session_scope(tenant_id) as session:
            approval = (
                await session.execute(select(Approval).where(Approval.action_request_id == request_id))
            ).scalar_one()
            with pytest.raises(PermissionDenied):
                await decide(session, caller_for(tenant_id, "admin-user", roles={"admin"}), approval.id, "approved")
            with pytest.raises(PermissionDenied):
                await decide(session, caller_for(tenant_id, "auditor-user", roles={"auditor"}), approval.id, "approved")
            assert approval.decision is None

    asyncio.run(scenario())


def test_decide_accepts_approver_in_required_group(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        _services, request_id = await _pending_approval(tenant_id, tmp_path)
        async with session_scope(tenant_id) as session:
            approval = (
                await session.execute(select(Approval).where(Approval.action_request_id == request_id))
            ).scalar_one()
            request = await decide(
                session, caller_for(tenant_id, "approver-user", roles={"approver"}, groups={"secops"}), approval.id, "approved"
            )
            assert request.state == "approved"
            assert approval.decided_by == "approver-user"

    asyncio.run(scenario())


def test_decide_refuses_approver_outside_required_group_even_when_admin(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        _services, request_id = await _pending_approval(tenant_id, tmp_path)
        async with session_scope(tenant_id) as session:
            approval = (
                await session.execute(select(Approval).where(Approval.action_request_id == request_id))
            ).scalar_one()
            with pytest.raises(PermissionDenied):
                await decide(
                    session,
                    caller_for(tenant_id, "approver-user", roles={"approver", "admin"}, groups={"other"}),
                    approval.id,
                    "approved",
                )

    asyncio.run(scenario())
