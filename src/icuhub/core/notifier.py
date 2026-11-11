"""Approval notifications through the tenant's ``smtp`` connection (FR-NTF-01..04)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.core.queue import enqueue
from icuhub.storage.db import session_scope
from icuhub.storage.models import ActionPlanRow, ActionRequest, Approval, Connection, Notification

__all__ = ["JOB_HANDLERS", "notify_approval", "run_notify_job"]


async def notify_approval(session: AsyncSession, approval: Approval) -> Notification | None:
    """Queue one approval notification when the tenant has an smtp connection."""
    request = await session.get(ActionRequest, approval.action_request_id)
    if request is None or request.action == "send_notification":
        return None  # never notify about the notification send itself
    smtp = (
        await session.execute(
            select(Connection).where(Connection.tenant_id == approval.tenant_id, Connection.kind == "smtp")
        )
    ).scalars().first()
    if smtp is None:
        return None
    plan = await session.get(ActionPlanRow, request.id)
    diff = json.dumps(plan.diff_json if plan else {}, sort_keys=True)[:2000]
    recipients = [f"{approval.approver_group}@approvals.icuhub"] if approval.approver_group else ["approvers@icuhub"]
    notification = Notification(
        tenant_id=approval.tenant_id,
        connection_id=smtp.id,
        template="approval_requested",
        recipients=recipients,
        subject=f"[ICUHUB] approval required: {request.action} ({request.classification})",
        body=(
            f"Action: {request.action}\n"
            f"Classification: {request.classification}\n"
            f"Requester: {request.caller_id}\n"
            f"Plan hash: {approval.plan_hash}\n"
            f"Expires at: {approval.expires_at.isoformat()}\n"
            f"Diff: {diff}\n"
            f"Approve with POST /v1/approvals/{approval.id}/decide"
        ),
    )
    session.add(notification)
    await session.flush()
    await enqueue(
        session,
        "notifications",
        "notify",
        {"notification_id": str(notification.id), "tenant_id": str(approval.tenant_id)},
        tenant_id=approval.tenant_id,
        dedupe_key=f"{approval.tenant_id}:notify:{notification.id}",
    )
    return notification


async def run_notify_job(payload: dict[str, Any], lease: Any = None) -> dict[str, Any]:
    """Worker handler for the ``notify`` job kind.

    Notification sends are system consequences of an already-approved action: the send
    itself is auto-approved by the system caller (never a second human approval loop),
    then executed through the normal apply path so audit and outbox stay intact.
    """
    from icuhub.core.actions import decide, run_apply_job, submit_action  # noqa: PLC0415
    from icuhub.core.auth_types import Caller  # noqa: PLC0415

    tenant_id = uuid.UUID(payload["tenant_id"])
    async with session_scope(tenant_id) as session:
        notification = await session.get(Notification, uuid.UUID(payload["notification_id"]))
        if notification is None or notification.state == "sent":
            return {"skipped": True}
        caller = Caller(id="notifier", tenant_id=tenant_id, roles=frozenset({"system"}))
        request = await submit_action(
            session,
            caller,
            notification.connection_id,
            "send_notification",
            {
                "recipients": notification.recipients,
                "subject": notification.subject,
                "body": notification.body,
            },
            idempotency_key=f"notify:{notification.id}",
        )
        request_id = request.id
        state = request.state
        if state == "pending_approval":
            approval = (
                await session.execute(
                    select(Approval).where(Approval.action_request_id == request.id, Approval.decision.is_(None))
                )
            ).scalar_one()
            auto = Caller(id="notifier-auto-approval", tenant_id=tenant_id, roles=frozenset({"approver"}))
            request = await decide(session, auto, approval.id, "approved", reason="system notification send")
            state = request.state
    if state in ("approved", "accepted_async"):
        outcome = await run_apply_job({"action_request_id": str(request_id), "tenant_id": str(tenant_id)})
        state = outcome["state"]
    async with session_scope(tenant_id) as session:
        notification = await session.get(Notification, uuid.UUID(payload["notification_id"]))
        if notification is not None:
            if state in ("succeeded", "no_op"):
                notification.state = "sent"
                notification.sent_at = datetime.now(UTC)
            elif state in ("failed", "denied", "rejected", "stale_plan", "unverified"):
                notification.state = "failed"
                notification.error = state
        return {"state": state}


JOB_HANDLERS = {"notify": run_notify_job}
